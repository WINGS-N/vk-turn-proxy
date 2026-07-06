package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"sync"
	"time"
)

const (
	groupRefreshSlackDuration      = 2 * time.Minute
	groupFallbackLifetime          = 10 * time.Minute
	groupProactiveRefreshFactor    = 4
	groupProactiveRefreshDiv       = 5
	groupRetryCooldown             = 90 * time.Second
	groupSoftRetryCooldown         = 10 * time.Second
	groupBackgroundRefreshInterval = 15 * time.Second
)

type credFetcher func(ctx context.Context, link string, allowInteractive bool) (turnCred, error)

type credGroup struct {
	id             int
	mu             sync.Mutex
	cond           *sync.Cond
	cred           turnCred
	valid          bool
	bornAt         time.Time
	lifetime       time.Duration
	refreshing     bool
	lastRefreshErr error
	assignedIdx    int
	prefetching    bool
	retryAfter     time.Time
	generation     uint64
}

type groupedCredsManager struct {
	ctx       context.Context
	cancel    context.CancelFunc
	groups    []*credGroup
	groupSize int
	tracker   *linkHealthTracker
	fetch     credFetcher
}

func newGroupedCredsManager(ctx context.Context, numGroups, groupSize int, tracker *linkHealthTracker, fetch credFetcher) *groupedCredsManager {
	if numGroups < 1 {
		numGroups = 1
	}
	if groupSize < 1 {
		groupSize = 1
	}
	mgrCtx, cancel := context.WithCancel(ctx)
	mgr := &groupedCredsManager{
		ctx:       mgrCtx,
		cancel:    cancel,
		groupSize: groupSize,
		tracker:   tracker,
		fetch:     fetch,
		groups:    make([]*credGroup, numGroups),
	}
	primaryCount := len(tracker.primary)
	for i := 0; i < numGroups; i++ {
		g := &credGroup{
			id:          i,
			assignedIdx: i % primaryCount,
		}
		g.cond = sync.NewCond(&g.mu)
		mgr.groups[i] = g
	}
	tracker.start(mgrCtx)
	go mgr.runBackgroundRefresh()
	return mgr
}

// runBackgroundRefresh keeps every group's creds warm independently of worker
// recycling. The only other refresh trigger is a worker re-allocating (acquire),
// so without this a quiet or stalled recycle cadence lets a group's creds lapse
// and all of its workers die. Groups are refreshed one at a time to avoid hitting
// the VK token chain with a simultaneous wave.
func (m *groupedCredsManager) runBackgroundRefresh() {
	ticker := time.NewTicker(groupBackgroundRefreshInterval)
	defer ticker.Stop()
	for {
		select {
		case <-m.ctx.Done():
			return
		case <-ticker.C:
			for _, g := range m.groups {
				g.mu.Lock()
				due := g.dueForBackgroundRefresh()
				if due {
					g.prefetching = true
				}
				g.mu.Unlock()
				if due {
					g.runPrefetch(m)
				}
			}
		}
	}
}

func (m *groupedCredsManager) Stop() {
	m.cancel()
	m.tracker.Stop()
}

func (m *groupedCredsManager) groupForWorker(workerID int) *credGroup {
	if workerID < 0 {
		workerID = 0
	}
	idx := (workerID / m.groupSize) % len(m.groups)
	return m.groups[idx]
}

func (m *groupedCredsManager) GetCredsForWorker(workerID int) (string, string, string, error) {
	g := m.groupForWorker(workerID)
	cred, err := g.acquire(m, true)
	if err != nil {
		return "", "", "", err
	}
	return cred.user, cred.pass, pickStreamServerAddr(workerID, cred.addrs), nil
}

// WorkerCredGeneration returns a counter that increments every time the
// worker's credential group fetches fresh TURN credentials. A worker captures
// it at allocate time and recycles its TURN allocation when it changes, so the
// new pion client re-auths CreatePermission with the rotated username/password
// instead of failing the periodic permission refresh with a 400.
func (m *groupedCredsManager) WorkerCredGeneration(workerID int) uint64 {
	g := m.groupForWorker(workerID)
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.generation
}

// ReportSetupFailure advances the rotation offset for the worker and marks the
// failing TURN address as cooling-down, so subsequent GetCredsForWorker calls
// hand out a different endpoint within the same credential.
func (m *groupedCredsManager) ReportSetupFailure(workerID int, addr string) {
	rotateStreamServer(workerID)
	markTURNServerCooldown(addr)
}

func (m *groupedCredsManager) ReportWorkerError(workerID int, err error) {
	if err == nil {
		return
	}
	kind := classifyLinkError(err)
	if kind == linkErrorKindNone {
		return
	}
	g := m.groupForWorker(workerID)
	g.mu.Lock()
	idx := g.assignedIdx
	valid := g.valid
	g.mu.Unlock()
	if !valid {
		return
	}
	link := m.tracker.primaryAt(idx)
	if link == nil {
		return
	}
	if g.cred.isSecondaryLink {
		if m.tracker.secondary != nil {
			link = m.tracker.secondary
		}
	}
	m.tracker.MarkWorkerError(link, kind)
	if !link.isAlive(time.Now().UnixMilli()) {
		m.invalidateGroupsBoundTo(link)
	}
}

func (m *groupedCredsManager) invalidateGroupsBoundTo(h *linkHealth) {
	for _, g := range m.groups {
		g.mu.Lock()
		bound := false
		if h.isSecondary {
			bound = g.cred.isSecondaryLink
		} else if g.assignedIdx == h.indexHint {
			bound = true
		}
		if bound {
			g.valid = false
			g.cond.Broadcast()
		}
		g.mu.Unlock()
	}
}

func (g *credGroup) effectiveLifetime() time.Duration {
	if g.lifetime > 0 {
		return g.lifetime
	}
	return groupFallbackLifetime
}

func (g *credGroup) expired() bool {
	if !g.valid {
		return true
	}
	deadline := g.bornAt.Add(g.effectiveLifetime() - groupRefreshSlackDuration)
	return time.Now().After(deadline)
}

func (g *credGroup) shouldPrefetch() bool {
	if !g.valid || g.prefetching {
		return false
	}
	threshold := g.bornAt.Add(g.effectiveLifetime() * groupProactiveRefreshFactor / groupProactiveRefreshDiv)
	return time.Now().After(threshold)
}

// trulyExpired reports whether the cred is past its usable life. effectiveLifetime
// already subtracts a safety margin from the server's stated expiry, so the cred
// stays usable right up to bornAt+effectiveLifetime; expired() trips earlier (minus
// the refresh slack) only to schedule a proactive refresh, not to stop serving.
func (g *credGroup) trulyExpired() bool {
	if !g.valid {
		return true
	}
	return time.Now().After(g.bornAt.Add(g.effectiveLifetime()))
}

// dueForBackgroundRefresh reports whether a valid, idle group has aged enough to
// refresh proactively (at the prefetch threshold or the conservative expiry,
// whichever comes first) and is not inside a retry cooldown.
func (g *credGroup) dueForBackgroundRefresh() bool {
	if !g.valid || g.prefetching || g.refreshing {
		return false
	}
	if !g.retryAfter.IsZero() && time.Now().Before(g.retryAfter) {
		return false
	}
	return g.shouldPrefetch() || g.expired()
}

func (g *credGroup) acquire(mgr *groupedCredsManager, allowInteractive bool) (turnCred, error) {
	g.mu.Lock()
	for {
		if g.valid && !g.expired() {
			cred := g.cred
			triggerPrefetch := g.shouldPrefetch()
			if triggerPrefetch {
				g.prefetching = true
			}
			g.mu.Unlock()
			if triggerPrefetch {
				go g.runPrefetch(mgr)
			}
			return cred, nil
		}
		if g.refreshing {
			g.cond.Wait()
			continue
		}
		if !g.retryAfter.IsZero() && time.Now().Before(g.retryAfter) {
			// Keep serving the existing cred while it is still genuinely usable
			// instead of erroring the worker out: a transient fetch failure must not
			// black-hole the whole group and kill its allocations.
			if g.valid && !g.trulyExpired() {
				cred := g.cred
				g.mu.Unlock()
				return cred, nil
			}
			err := g.lastRefreshErr
			if err == nil {
				err = errors.New("creds fetch backoff active")
			}
			g.mu.Unlock()
			return turnCred{}, err
		}
		g.refreshing = true
		g.mu.Unlock()

		cred, link, err := mgr.fetchForGroup(g, allowInteractive)

		g.mu.Lock()
		g.refreshing = false
		if err != nil {
			g.lastRefreshErr = err
			// Soft path: if the previous cred is still usable, keep handing it out
			// and retry soon rather than locking the group out for the full cooldown
			// (which black-holes every worker until the cred actually lapses).
			if g.valid && !g.trulyExpired() {
				g.retryAfter = time.Now().Add(groupSoftRetryCooldown)
				cred := g.cred
				g.cond.Broadcast()
				g.mu.Unlock()
				return cred, nil
			}
			g.retryAfter = time.Now().Add(groupRetryCooldown)
			g.cond.Broadcast()
			g.mu.Unlock()
			return turnCred{}, err
		}
		g.cred = cred
		g.bornAt = time.Now()
		g.lifetime = cred.lifetime
		g.valid = true
		g.generation++
		g.assignedIdx = link.indexHint
		g.lastRefreshErr = nil
		g.retryAfter = time.Time{}
		g.cond.Broadcast()
		result := g.cred
		g.mu.Unlock()
		return result, nil
	}
}

func (g *credGroup) runPrefetch(mgr *groupedCredsManager) {
	defer func() {
		g.mu.Lock()
		g.prefetching = false
		g.mu.Unlock()
	}()
	cred, link, err := mgr.fetchForGroup(g, false)
	if err != nil {
		log.Printf("Group #%d prefetch failed: %v", g.id, err)
		return
	}
	g.mu.Lock()
	g.cred = cred
	g.bornAt = time.Now()
	g.lifetime = cred.lifetime
	g.valid = true
	g.generation++
	g.assignedIdx = link.indexHint
	g.lastRefreshErr = nil
	g.retryAfter = time.Time{}
	g.mu.Unlock()
	log.Printf("Group #%d prefetched fresh creds via %s", g.id, link.url)
}

func (m *groupedCredsManager) fetchForGroup(g *credGroup, allowInteractive bool) (turnCred, *linkHealth, error) {
	g.mu.Lock()
	preferIdx := g.assignedIdx
	g.mu.Unlock()
	primaryCount := m.tracker.primaryLen()
	if primaryCount > 0 {
		if preferIdx < 0 {
			preferIdx = 0
		}
		preferIdx = preferIdx % primaryCount
	}
	for attempt := 0; attempt < primaryCount; attempt++ {
		h := m.tracker.PickPrimary((preferIdx + attempt) % primaryCount)
		if h == nil {
			break
		}
		cred, err := m.fetch(m.ctx, h.url, allowInteractive)
		if err == nil {
			cred.bornAt = time.Now()
			cred.isSecondaryLink = false
			m.tracker.MarkFetchSuccess(h)
			return cred, h, nil
		}
		m.tracker.MarkFetchFailure(h)
		log.Printf("Group #%d creds fetch via %s failed: %v", g.id, h.url, err)
	}
	if m.tracker.secondary != nil && m.tracker.secondary.isAlive(time.Now().UnixMilli()) {
		cred, err := m.fetch(m.ctx, m.tracker.secondary.url, allowInteractive)
		if err == nil {
			cred.bornAt = time.Now()
			cred.isSecondaryLink = true
			m.tracker.MarkFetchSuccess(m.tracker.secondary)
			log.Printf("Group #%d acquired creds via secondary link", g.id)
			return cred, m.tracker.secondary, nil
		}
		m.tracker.MarkFetchFailure(m.tracker.secondary)
		log.Printf("Group #%d secondary creds fetch failed: %v", g.id, err)
	}
	return turnCred{}, nil, fmt.Errorf("group %d: all VK links exhausted", g.id)
}
