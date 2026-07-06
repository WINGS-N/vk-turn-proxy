package main

import (
	"context"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cacggghp/vk-turn-proxy/appcontrolpb"
)

// patchResolver re-resolves a new VK TURN endpoint during an endpoint live-patch.
// Set once at engine build from the same resolver the boot peer used.
var patchResolver *protectedResolver

// patchLinkTracker backs a live VK-links patch: swap the link pool in place. The
// new pool is picked up on the next natural creds rotation, so no forced re-fetch.
var patchLinkTracker *linkHealthTracker

// wrapFailGen is the highest config generation on which a stream failed WRAP
// negotiation. A WRAP live-patch watches it to decide whether to roll back.
var wrapFailGen atomic.Uint64

// recordWrapFailure is called by a worker whose WRAP negotiation failed, tagged
// with the snapshot generation it was running. Monotonic max so a later, healthy
// migration is not tripped by a stale failure.
func recordWrapFailure(gen uint64) {
	for {
		cur := wrapFailGen.Load()
		if gen <= cur {
			return
		}
		if wrapFailGen.CompareAndSwap(cur, gen) {
			return
		}
	}
}

// workerRegistry tracks the active TURN streams: the config generation each has
// adopted (so a patch can tell when the fleet has migrated) and each one's cancel
// func (so a thread-count patch can drain individual streams). spawn creates one
// more worker for the active session and is stashed by startDtlsTurnWorkers.
type workerRegistry struct {
	mu      sync.Mutex
	gen     map[int]uint64
	cancels map[int]context.CancelFunc
	spawn   func(streamID byte)
}

var workers = &workerRegistry{
	gen:     make(map[int]uint64),
	cancels: make(map[int]context.CancelFunc),
}

func (r *workerRegistry) set(id int, g uint64) {
	r.mu.Lock()
	r.gen[id] = g
	r.mu.Unlock()
}

func (r *workerRegistry) register(id int, cancel context.CancelFunc) {
	r.mu.Lock()
	r.cancels[id] = cancel
	r.mu.Unlock()
}

func (r *workerRegistry) remove(id int) {
	r.mu.Lock()
	delete(r.gen, id)
	delete(r.cancels, id)
	r.mu.Unlock()
}

func (r *workerRegistry) setSpawn(fn func(streamID byte)) {
	r.mu.Lock()
	r.spawn = fn
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

// resize ramps the worker fleet up or down to target, one stream at a time so
// neither a spawn wave nor a drain wave hits at once. Ramp-up spawns fresh workers
// on the lowest free stream ids; ramp-down cancels the highest ids (their traffic
// re-routes over the surviving WG streams). Reports threads applied when done.
func (r *workerRegistry) resize(reqID string, target int) {
	if target < 1 {
		target = 1
	}
	if target > 250 {
		// stream ids are a byte on the wire; leave headroom under 256.
		target = 250
	}
	r.mu.Lock()
	spawn := r.spawn
	ids := make([]int, 0, len(r.cancels))
	used := make(map[int]bool, len(r.cancels))
	for id := range r.cancels {
		ids = append(ids, id)
		used[id] = true
	}
	r.mu.Unlock()
	sort.Ints(ids)
	cur := len(ids)
	if target == cur || (target > cur && spawn == nil) {
		publishPatchStatus(reqID, "threads", "applied", "")
		return
	}
	publishPatchStatus(reqID, "threads", "applying", "")
	if target > cur {
		need := target - cur
		go func() {
			spawned := 0
			for id := 0; id < 256 && spawned < need; id++ {
				if used[id] {
					continue
				}
				spawn(byte(id))
				spawned++
				time.Sleep(500 * time.Millisecond)
			}
			publishPatchStatus(reqID, "threads", "applied", "")
		}()
		return
	}
	drop := append([]int(nil), ids[target:]...) // highest (cur-target) ids
	go func() {
		for i := len(drop) - 1; i >= 0; i-- {
			r.cancelWorker(drop[i])
			time.Sleep(500 * time.Millisecond)
		}
		publishPatchStatus(reqID, "threads", "applied", "")
	}()
}

func (r *workerRegistry) cancelWorker(id int) {
	r.mu.Lock()
	c := r.cancels[id]
	r.mu.Unlock()
	if c != nil {
		c()
	}
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
	wrapMigrated := false
	if req.WrapMode != nil || req.WrapCipher != nil || req.WrapKeyHex != nil || req.WrapSendKey != nil {
		mode := next.wrapMode
		if req.WrapMode != nil {
			mode = req.GetWrapMode()
		}
		cipherSel, key, resolvedMode, err := resolveWrapConfig(mode, req.GetWrapCipher(), req.GetWrapKeyHex())
		sendKey := next.wrapSendKey
		if req.WrapSendKey != nil {
			sendKey = req.GetWrapSendKey()
		}
		switch {
		case err != nil:
			publishPatchStatus(reqID, "wrap", "failed", err.Error())
		case cur.wrapSendKey && !sendKey && resolvedMode != "off":
			// Turning in-band key delivery off while WRAP stays active cannot be done
			// live: new streams would negotiate WRAP without sending the key, but the
			// server has no matching preset for an auto-generated key (and we cannot
			// verify one), so the switch would silently break traffic. Keep the
			// previous WRAP and tell the app it needs a restart. next.wrap* already
			// holds the current values (copied from cur), so nothing migrates.
			publishPatchStatus(reqID, "wrap", "reverted_needs_restart",
				"turning off in-band WRAP key can only take effect on the next start")
		default:
			next.wrapCipher = cipherSel
			next.wrapKey = key
			next.wrapMode = resolvedMode
			next.wrapSendKey = sendKey
			wrapMigrated = true
		}
	}

	// Thread count: spawn or drain workers to reach the target, one at a time.
	// Independent of the snapshot migration (it changes the fleet size, not the
	// per-stream config).
	if req.Threads != nil {
		go workers.resize(reqID, int(req.GetThreads()))
	}

	// VK links: swap the pool only. A TURN credential, once fetched, works
	// independently of the join link it came from (the link just mints the
	// allocation), so existing streams keep serving on their current creds and the
	// new pool is picked up on the next natural creds rotation (TTL) or by newly
	// spawned workers. No forced re-fetch or recycle - traffic is never interrupted.
	if links := req.GetVkLinks(); links != nil {
		if patchLinkTracker == nil {
			publishPatchStatus(reqID, "vk_links", "failed", "VK links are not patchable in this mode")
		} else {
			publishPatchStatus(reqID, "vk_links", "applying", "")
			patchLinkTracker.setPrimaryLinks(links.GetLinks())
			publishPatchStatus(reqID, "vk_links", "applied", "")
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

	if len(migrateFields) == 0 && !authChanged && !wrapMigrated {
		return
	}
	if authChanged {
		migrateFields = append(migrateFields, "vk_auth")
	}
	for _, f := range migrateFields {
		publishPatchStatus(reqID, f, "applying", "")
	}
	if wrapMigrated {
		publishPatchStatus(reqID, "wrap", "applying", "")
	}
	g := swapLive(&next)
	// The generic fields are applied once the fleet has migrated. WRAP is watched
	// separately because it can break on a new stream (see watchWrapMigration).
	if len(migrateFields) > 0 {
		go waitMigrated(reqID, migrateFields, g)
	}
	if wrapMigrated {
		go watchWrapMigration(reqID, *cur, g)
	}
}

// watchWrapMigration decides the outcome of a WRAP live-change. If a new-snapshot
// stream fails WRAP negotiation (e.g. in-band delivery was turned off but the
// server had no preset key, so a "required" stream is rejected), the whole live
// switch is unsafe: roll the WRAP fields back to the previous snapshot so every
// stream keeps the old, working WRAP, and tell the app the change will only take
// effect on the next relay restart. Otherwise, once the fleet has migrated, report
// applied. In the common case (in-band stays on) new streams just negotiate the
// fresh key and this reports applied with no rollback.
func watchWrapMigration(reqID string, prev liveSnapshot, g uint64) {
	deadline := time.Now().Add(2 * time.Minute)
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()
	for range ticker.C {
		if wrapFailGen.Load() >= g {
			// Roll WRAP back to the previous snapshot, keeping any other patched
			// fields (endpoint/host/port) that migrated in the same swap.
			roll := *currentLive()
			roll.wrapCipher = prev.wrapCipher
			roll.wrapKey = prev.wrapKey
			roll.wrapMode = prev.wrapMode
			roll.wrapSendKey = prev.wrapSendKey
			swapLive(&roll)
			publishPatchStatus(reqID, "wrap", "reverted_needs_restart",
				"WRAP negotiation failed on a new stream; kept the previous WRAP")
			return
		}
		if workers.allAtLeast(g) || time.Now().After(deadline) {
			publishPatchStatus(reqID, "wrap", "applied", "")
			return
		}
	}
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
	if req.UserDns != nil {
		out = append(out, "user_dns")
	}
	if req.CredsGroupSize != nil {
		out = append(out, "creds_group_size")
	}
	return out
}
