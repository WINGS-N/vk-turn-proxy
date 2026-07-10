package main

import (
	"context"
	"log"
	"sync"
	"time"

	"github.com/cacggghp/vk-turn-proxy/internal/controlpath"
	"github.com/cacggghp/vk-turn-proxy/internal/panelclient"
)

// clientTrafficUsage caches the panel-reported traffic-limit state for one
// managed client so the node can echo used/remaining in its heartbeats.
type clientTrafficUsage struct {
	present        bool
	limitBytes     uint64
	usedBytes      uint64
	remainingBytes uint64
	disabled       bool
}

type clientUsageStore struct {
	mu       sync.RWMutex
	byClient map[string]clientTrafficUsage
}

var clientUsage = &clientUsageStore{byClient: map[string]clientTrafficUsage{}}

func (s *clientUsageStore) replace(rows []panelclient.ClientUsage) {
	next := make(map[string]clientTrafficUsage, len(rows))
	for _, r := range rows {
		if r.ClientID == "" {
			continue
		}
		next[r.ClientID] = clientTrafficUsage{
			present:        true,
			limitBytes:     r.LimitBytes,
			usedBytes:      r.UsedBytes,
			remainingBytes: r.RemainingBytes,
			disabled:       r.Disabled,
		}
	}
	s.mu.Lock()
	s.byClient = next
	s.mu.Unlock()
}

func (s *clientUsageStore) get(clientID string) (clientTrafficUsage, bool) {
	if clientID == "" {
		return clientTrafficUsage{}, false
	}
	s.mu.RLock()
	u, ok := s.byClient[clientID]
	s.mu.RUnlock()
	return u, ok
}

// usageResolver fetches per-client traffic-limit usage from the panel;
// panelclient.Client satisfies it.
type usageResolver interface {
	GetClientUsage(ctx context.Context, nodeID string) ([]panelclient.ClientUsage, error)
}

// clientUsagePollInterval is how often the node refreshes usage from the panel.
const clientUsagePollInterval = 30 * time.Second

// startClientUsagePoller refreshes the usage cache from the panel on a ticker
// until ctx is cancelled. Runs only when the DTLS PROVISION path is configured
// (there is a panel to ask).
func startClientUsagePoller(ctx context.Context, resolver usageResolver, nodeID string) {
	go func() {
		ticker := time.NewTicker(clientUsagePollInterval)
		defer ticker.Stop()
		for {
			refreshClientUsage(ctx, resolver, nodeID)
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}
		}
	}()
}

func refreshClientUsage(ctx context.Context, resolver usageResolver, nodeID string) {
	cctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	rows, err := resolver.GetClientUsage(cctx, nodeID)
	if err != nil {
		log.Printf("client usage poll: %v", err)
		return
	}
	clientUsage.replace(rows)
}

// applyUsageToHeartbeat fills a heartbeat meta's traffic fields from the cached
// usage for clientID. A blank id or an unknown client leaves the fields absent,
// so the app simply shows no limit for that session.
func applyUsageToHeartbeat(meta *controlpath.HeartbeatMeta, clientID string) {
	u, ok := clientUsage.get(clientID)
	if !ok {
		return
	}
	meta.TrafficPresent = true
	meta.TrafficLimitBytes = u.limitBytes
	meta.TrafficUsedBytes = u.usedBytes
	meta.TrafficRemainingBytes = u.remainingBytes
	meta.TrafficDisabled = u.disabled
}
