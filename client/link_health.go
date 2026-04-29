package main

import (
	"context"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type linkErrorKind int

const (
	linkErrorKindNone linkErrorKind = iota
	linkErrorKindStreamClose
	linkErrorKindQuota
	linkErrorKindStunDeath
	linkErrorKindGeneric
)

const (
	linkStreamCloseThreshold  = 8
	linkStreamCloseCooldown   = 60 * time.Second
	linkQuotaThreshold        = 5
	linkQuotaCooldown         = 5 * time.Minute
	linkStunDeathThreshold    = 8
	linkStunDeathCooldown     = 5 * time.Minute
	linkFetchFailureThreshold = 3
	linkFetchFailureCooldown  = 90 * time.Second
	linkErrorDecayInterval    = 30 * time.Second
)

type linkHealth struct {
	url              string
	indexHint        int
	isSecondary      bool
	failureCount     atomic.Int32
	streamCloseCount atomic.Int32
	quotaCount       atomic.Int32
	stunDeathCount   atomic.Int32
	deadUntilUnixMs  atomic.Int64
	lastSuccessAtMs  atomic.Int64
	lastFailureAtMs  atomic.Int64
}

func (h *linkHealth) isAlive(nowMs int64) bool {
	return h.deadUntilUnixMs.Load() <= nowMs
}

func (h *linkHealth) markDead(d time.Duration) {
	deadline := time.Now().Add(d).UnixMilli()
	for {
		current := h.deadUntilUnixMs.Load()
		if deadline <= current {
			return
		}
		if h.deadUntilUnixMs.CompareAndSwap(current, deadline) {
			return
		}
	}
}

type linkHealthTracker struct {
	primary   []*linkHealth
	secondary *linkHealth
	stopCh    chan struct{}
	stopOnce  sync.Once
}

func newLinkHealthTracker(primary []string, secondary string) (*linkHealthTracker, error) {
	cleanedPrimary := make([]*linkHealth, 0, len(primary))
	seen := make(map[string]struct{}, len(primary))
	for idx, raw := range primary {
		normalized := strings.TrimSpace(raw)
		if normalized == "" {
			continue
		}
		if _, dup := seen[normalized]; dup {
			continue
		}
		seen[normalized] = struct{}{}
		cleanedPrimary = append(cleanedPrimary, &linkHealth{url: normalized, indexHint: idx})
	}
	if len(cleanedPrimary) == 0 {
		return nil, errors.New("at least one VK link is required")
	}

	tracker := &linkHealthTracker{
		primary: cleanedPrimary,
		stopCh:  make(chan struct{}),
	}
	secondary = strings.TrimSpace(secondary)
	if secondary != "" {
		if _, dup := seen[secondary]; !dup {
			tracker.secondary = &linkHealth{url: secondary, indexHint: -1, isSecondary: true}
		}
	}
	return tracker, nil
}

func (t *linkHealthTracker) start(ctx context.Context) {
	go t.decayLoop(ctx)
}

func (t *linkHealthTracker) Stop() {
	t.stopOnce.Do(func() {
		close(t.stopCh)
	})
}

func (t *linkHealthTracker) decayLoop(ctx context.Context) {
	ticker := time.NewTicker(linkErrorDecayInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.stopCh:
			return
		case <-ticker.C:
			t.decayCounters()
		}
	}
}

func (t *linkHealthTracker) decayCounters() {
	all := t.allLinks()
	for _, h := range all {
		halveCounter(&h.streamCloseCount)
		halveCounter(&h.quotaCount)
		halveCounter(&h.stunDeathCount)
	}
}

func halveCounter(c *atomic.Int32) {
	for {
		current := c.Load()
		if current <= 0 {
			return
		}
		next := current / 2
		if c.CompareAndSwap(current, next) {
			return
		}
	}
}

func (t *linkHealthTracker) allLinks() []*linkHealth {
	all := make([]*linkHealth, 0, len(t.primary)+1)
	all = append(all, t.primary...)
	if t.secondary != nil {
		all = append(all, t.secondary)
	}
	return all
}

func (t *linkHealthTracker) PickPrimary(preferIdx int) *linkHealth {
	now := time.Now().UnixMilli()
	n := len(t.primary)
	if n == 0 {
		return nil
	}
	if preferIdx < 0 {
		preferIdx = 0
	}
	for i := 0; i < n; i++ {
		idx := (preferIdx + i) % n
		h := t.primary[idx]
		if h.isAlive(now) {
			return h
		}
	}
	return nil
}

func (t *linkHealthTracker) PickWithSecondary(preferIdx int) *linkHealth {
	if h := t.PickPrimary(preferIdx); h != nil {
		return h
	}
	if t.secondary != nil && t.secondary.isAlive(time.Now().UnixMilli()) {
		return t.secondary
	}
	return nil
}

func (t *linkHealthTracker) MarkFetchSuccess(h *linkHealth) {
	if h == nil {
		return
	}
	h.failureCount.Store(0)
	h.lastSuccessAtMs.Store(time.Now().UnixMilli())
}

func (t *linkHealthTracker) MarkFetchFailure(h *linkHealth) {
	if h == nil {
		return
	}
	count := h.failureCount.Add(1)
	h.lastFailureAtMs.Store(time.Now().UnixMilli())
	if count >= linkFetchFailureThreshold {
		h.markDead(linkFetchFailureCooldown)
	}
}

func (t *linkHealthTracker) MarkWorkerError(h *linkHealth, kind linkErrorKind) {
	if h == nil || kind == linkErrorKindNone {
		return
	}
	switch kind {
	case linkErrorKindStreamClose:
		if h.streamCloseCount.Add(1) >= linkStreamCloseThreshold {
			h.markDead(linkStreamCloseCooldown)
		}
	case linkErrorKindQuota:
		if h.quotaCount.Add(1) >= linkQuotaThreshold {
			h.markDead(linkQuotaCooldown)
		}
	case linkErrorKindStunDeath:
		if h.stunDeathCount.Add(1) >= linkStunDeathThreshold {
			h.markDead(linkStunDeathCooldown)
		}
	case linkErrorKindGeneric:
	}
	h.lastFailureAtMs.Store(time.Now().UnixMilli())
}

func classifyLinkError(err error) linkErrorKind {
	if err == nil {
		return linkErrorKindNone
	}
	msg := strings.ToLower(err.Error())
	switch {
	case strings.Contains(msg, "stream closed"):
		return linkErrorKindStreamClose
	case strings.Contains(msg, "turn quota"),
		strings.Contains(msg, "quota"),
		strings.Contains(msg, "486"):
		return linkErrorKindQuota
	case strings.Contains(msg, "attribute not found"),
		strings.Contains(msg, "error 29"),
		strings.Contains(msg, "unauthorized"),
		strings.Contains(msg, "allocation mismatch"),
		strings.Contains(msg, "error 508"),
		strings.Contains(msg, "cannot create socket"):
		return linkErrorKindStunDeath
	}
	return linkErrorKindGeneric
}
