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
	groupRefreshSlackDuration   = 2 * time.Minute
	groupFallbackLifetime       = 10 * time.Minute
	groupProactiveRefreshFactor = 4
	groupProactiveRefreshDiv    = 5
	groupRetryCooldown          = 90 * time.Second
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
	return mgr
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
	return cred.user, cred.pass, cred.addr, nil
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
	if idx < 0 || idx >= len(m.tracker.primary) {
		return
	}
	link := m.tracker.primary[idx]
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
			g.retryAfter = time.Now().Add(groupRetryCooldown)
			g.cond.Broadcast()
			g.mu.Unlock()
			return turnCred{}, err
		}
		g.cred = cred
		g.bornAt = time.Now()
		g.lifetime = cred.lifetime
		g.valid = true
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
	primaryCount := len(m.tracker.primary)
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
