package main

import (
	"context"
	"strings"
	"sync"
	"time"

	"github.com/cacggghp/vk-turn-proxy/appcontrolpb"
)

// patchResolver re-resolves a new VK TURN endpoint during an endpoint live-patch.
// Set once at engine build from the same resolver the boot peer used.
var patchResolver *protectedResolver

// workerRegistry tracks the config generation each active TURN stream has adopted,
// so a patch can tell when the whole fleet has migrated onto the new snapshot and
// report the field as applied. It is also the seam the thread ramp/drain supervisor
// builds on (a later step).
type workerRegistry struct {
	mu  sync.Mutex
	gen map[int]uint64
}

var workers = &workerRegistry{gen: make(map[int]uint64)}

func (r *workerRegistry) set(id int, g uint64) {
	r.mu.Lock()
	r.gen[id] = g
	r.mu.Unlock()
}

func (r *workerRegistry) remove(id int) {
	r.mu.Lock()
	delete(r.gen, id)
	r.mu.Unlock()
}

// allAtLeast reports whether every currently-registered stream has adopted a
// generation >= g. An empty fleet counts as migrated.
func (r *workerRegistry) allAtLeast(g uint64) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, v := range r.gen {
		if v < g {
			return false
		}
	}
	return true
}

// applyPatch applies a PatchConfig delta live. DNS flips instantly; the snapshot
// bundle (endpoint / host / port / WRAP) and VK auth mode migrate the worker fleet
// onto a new snapshot one stream at a time. Per-field progress is reported over
// StreamEvents. Fields not yet live-patchable are reported reverted_needs_restart.
func applyPatch(req *appcontrolpb.PatchConfigRequest) {
	reqID := req.GetRequestId()

	// DNS mode: the resolver reads the mode atomically on every resolve, so this is
	// an instant global flip with no migration.
	if req.DnsMode != nil {
		publishPatchStatus(reqID, "dns", "applying", "")
		setDnsMode(strings.ToLower(strings.TrimSpace(req.GetDnsMode())))
		publishPatchStatus(reqID, "dns", "applied", "")
	}

	// Build the next snapshot from the current one plus the present deltas.
	cur := currentLive()
	next := *cur
	next.gen = 0 // stamped by swapLive
	var migrateFields []string

	if req.TurnHost != nil {
		next.host = strings.TrimSpace(req.GetTurnHost())
		migrateFields = append(migrateFields, "turn_host")
	}
	if req.TurnPort != nil {
		next.port = strings.TrimSpace(req.GetTurnPort())
		migrateFields = append(migrateFields, "turn_port")
	}
	if req.Peer != nil {
		if patchResolver == nil {
			publishPatchStatus(reqID, "peer", "failed", "no resolver")
		} else {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			addr, err := patchResolver.ResolveUDPAddrPreferIPv4(ctx, strings.TrimSpace(req.GetPeer()))
			cancel()
			if err != nil {
				publishPatchStatus(reqID, "peer", "failed", err.Error())
			} else {
				next.peer = addr
				migrateFields = append(migrateFields, "peer")
			}
		}
	}
	// WRAP is patched as one coherent group: the app sends the full set (mode +
	// cipher + key + send-key) whenever any WRAP field changes.
	if req.WrapMode != nil || req.WrapCipher != nil || req.WrapKeyHex != nil || req.WrapSendKey != nil {
		mode := next.wrapMode
		if req.WrapMode != nil {
			mode = req.GetWrapMode()
		}
		cipherSel, key, resolvedMode, err := resolveWrapConfig(mode, req.GetWrapCipher(), req.GetWrapKeyHex())
		if err != nil {
			publishPatchStatus(reqID, "wrap", "failed", err.Error())
		} else {
			next.wrapCipher = cipherSel
			next.wrapKey = key
			next.wrapMode = resolvedMode
			if req.WrapSendKey != nil {
				next.wrapSendKey = req.GetWrapSendKey()
			}
			migrateFields = append(migrateFields, "wrap")
		}
	}

	// VK auth mode: the global is read per credential fetch and per recycle, so a
	// flip plus a fleet migration switches every stream to the new mode. Works both
	// ways (anonymous <-> account).
	authChanged := false
	if req.VkAuth != nil {
		mode := strings.ToLower(strings.TrimSpace(req.GetVkAuth()))
		if mode != "account" {
			mode = "anonymous"
		}
		setVkAuthMode(mode)
		authChanged = true
	}

	// Fields that need scaffolding not yet built (thread ramp/drain, live VK links,
	// user-DNS, creds group size) are not live-applied yet: tell the app they will
	// take effect on the next relay restart.
	for _, f := range needsRestartFields(req) {
		publishPatchStatus(reqID, f, "reverted_needs_restart", "not live-patchable yet")
	}

	if len(migrateFields) == 0 && !authChanged {
		return
	}
	if authChanged {
		migrateFields = append(migrateFields, "vk_auth")
	}
	for _, f := range migrateFields {
		publishPatchStatus(reqID, f, "applying", "")
	}
	g := swapLive(&next)
	go waitMigrated(reqID, migrateFields, g)
}

// waitMigrated reports each field applied once the whole fleet has recycled onto
// generation g. Best-effort: after a generous deadline it reports applied anyway,
// since migration is eventually consistent (a lagging stream still adopts g on its
// next reconnect).
func waitMigrated(reqID string, fields []string, g uint64) {
	deadline := time.Now().Add(2 * time.Minute)
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()
	for range ticker.C {
		if workers.allAtLeast(g) || time.Now().After(deadline) {
			break
		}
	}
	for _, f := range fields {
		publishPatchStatus(reqID, f, "applied", "")
	}
}

// needsRestartFields lists present patch fields the relay cannot live-apply yet.
//
//nolint:unused
func needsRestartFields(req *appcontrolpb.PatchConfigRequest) []string {
	var out []string
	if req.Threads != nil {
		out = append(out, "threads")
	}
	if req.GetVkLinks() != nil {
		out = append(out, "vk_links")
	}
	if req.UserDns != nil {
		out = append(out, "user_dns")
	}
	if req.CredsGroupSize != nil {
		out = append(out, "creds_group_size")
	}
	return out
}
