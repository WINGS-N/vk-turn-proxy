package main

import (
	"context"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cacggghp/vk-turn-proxy/sessionproto"
)

type packetDispatcher struct{}

type streamRuntime struct {
	id           byte
	turnReady    atomic.Bool
	dtlsReady    atomic.Bool
	lastAliveAt  atomic.Int64
	registeredAt int64
}

type sessionRuntime struct {
	lock                      sync.RWMutex
	mode                      sessionproto.Mode
	statusEnabled             bool
	streams                   map[byte]*streamRuntime
	leaderStreamID            byte
	leaderStreamValid         bool
	controlHeartbeatSupported atomic.Bool

	dispatchMu        sync.Mutex
	dispatchSlots     []dispatchSlot
	dispatchRRIdx     int
	dispatchChunkLeft int
	dispatchActive    bool

	credsManager *groupedCredsManager
}

// dispatchChunkSize is the number of consecutive WireGuard packets sent to one
// relay before advancing. Per-packet round-robin (chunk=1) scatters a single
// tunneled TCP flow's packets across relays with differing latency, which the
// peer reads as reorder/loss and collapses the congestion window. A chunk of 8
// fits inside one initial TCP congestion window, so reorder only happens at
// chunk boundaries, which WireGuard's replay window absorbs. Multi-flow
// aggregate is unaffected since chunks are small relative to total volume.
const dispatchChunkSize = 8

type dispatchSlot struct {
	streamID byte
	sendCh   chan *UDPPacket
	// stream carries the liveness stamp the workers write on every datagram, so
	// dispatch can tell a relay that is still carrying traffic from one that has
	// gone quiet without taking any lock.
	stream *streamRuntime
}

// dispatchStaleAfter is how long a relay may go without carrying a datagram
// before dispatch starts routing around it.
//
// VK tears down and rotates its TURN relays as a matter of course, so a stream
// dying mid-session is normal rather than exceptional. The worker only leaves
// the rotation when its goroutine returns, and until then dispatch keeps handing
// it packets that die in its queue. Two seconds is far longer than any gap in a
// stream that is actually carrying a transfer, and far shorter than the time a
// torn stream lingers.
const dispatchStaleAfter = 2000 // milliseconds

func newSessionRuntime(
	ctx context.Context,
	mode sessionproto.Mode,
	protocolVersion uint32,
	sessionID []byte,
	statusEnabled bool,
	dispatcher *packetDispatcher,
) *sessionRuntime {
	_ = ctx
	_ = protocolVersion
	_ = sessionID
	_ = dispatcher
	return &sessionRuntime{
		mode:           mode,
		statusEnabled:  statusEnabled,
		streams:        make(map[byte]*streamRuntime),
		dispatchActive: true,
	}
}

func (runtime *sessionRuntime) DispatchesInbound() bool {
	if runtime == nil {
		return false
	}
	return runtime.dispatchActive
}

func (runtime *sessionRuntime) AttachCredsManager(mgr *groupedCredsManager) {
	if runtime == nil {
		return
	}
	runtime.credsManager = mgr
}

func (runtime *sessionRuntime) NoteSessionError(streamID byte, err error) {
	if runtime == nil || err == nil {
		return
	}
	if runtime.credsManager == nil {
		return
	}
	runtime.credsManager.ReportWorkerError(int(streamID), err)
}

func (runtime *sessionRuntime) BindDispatchChannel(streamID byte, packets chan *UDPPacket) {
	if runtime == nil || packets == nil {
		return
	}
	runtime.dispatchMu.Lock()
	defer runtime.dispatchMu.Unlock()
	for i := range runtime.dispatchSlots {
		if runtime.dispatchSlots[i].streamID == streamID {
			runtime.dispatchSlots[i].sendCh = packets
			return
		}
	}
	runtime.dispatchSlots = append(runtime.dispatchSlots, dispatchSlot{
		streamID: streamID,
		sendCh:   packets,
		stream:   runtime.streams[streamID],
	})
}

func (runtime *sessionRuntime) UnbindDispatchChannel(streamID byte) {
	if runtime == nil {
		return
	}
	runtime.dispatchMu.Lock()
	defer runtime.dispatchMu.Unlock()
	for i, slot := range runtime.dispatchSlots {
		if slot.streamID == streamID {
			runtime.dispatchSlots = append(runtime.dispatchSlots[:i], runtime.dispatchSlots[i+1:]...)
			if len(runtime.dispatchSlots) == 0 {
				runtime.dispatchRRIdx = 0
			} else {
				runtime.dispatchRRIdx %= len(runtime.dispatchSlots)
			}
			runtime.dispatchChunkLeft = 0
			return
		}
	}
}

// RunInboundDispatchLoop drains whatever the reader could not place itself. With
// the reader dispatching inline this is the overflow path: it only runs when the
// relays were all busy at the moment a datagram arrived.
func (runtime *sessionRuntime) RunInboundDispatchLoop(ctx context.Context, inboundChan <-chan *UDPPacket) {
	if runtime == nil {
		return
	}
	activeInboundDispatcher.Store(runtime)
	defer activeInboundDispatcher.CompareAndSwap(runtime, nil)
	for {
		select {
		case <-ctx.Done():
			return
		case pkt, ok := <-inboundChan:
			if !ok {
				return
			}
			if !runtime.dispatchPacket(pkt) {
				packetPool.Put(pkt)
			}
		}
	}
}

func (runtime *sessionRuntime) dispatchPacket(pkt *UDPPacket) bool {
	runtime.dispatchMu.Lock()
	defer runtime.dispatchMu.Unlock()
	count := len(runtime.dispatchSlots)
	if count == 0 {
		return false
	}
	now := time.Now().UnixMilli()
	// First pass over the relays that are still carrying traffic. A torn relay
	// keeps accepting into its queue until its worker notices and unbinds, and
	// everything placed there in the meantime dies with it, so a stream that has
	// gone quiet is skipped rather than fed.
	if runtime.placePacket(pkt, count, now, true) {
		return true
	}
	// Nothing looked alive. That is also what an idle tunnel looks like, so fall
	// back to placing the packet anywhere rather than dropping it.
	return runtime.placePacket(pkt, count, now, false)
}

// placePacket walks the relays from the current rotation point and hands pkt to
// the first that takes it. When requireLive is set, relays that have not carried
// a datagram recently are passed over.
func (runtime *sessionRuntime) placePacket(pkt *UDPPacket, count int, now int64, requireLive bool) bool {
	start := runtime.dispatchRRIdx % count
	for i := 0; i < count; i++ {
		idx := (start + i) % count
		slot := runtime.dispatchSlots[idx]
		if requireLive && !slotIsLive(slot, now) {
			continue
		}
		select {
		case slot.sendCh <- pkt:
			if idx != start {
				// Current relay was full or gone; switch to this one and start a
				// fresh chunk on it.
				runtime.dispatchRRIdx = idx
				runtime.dispatchChunkLeft = 0
			}
			if runtime.dispatchChunkLeft <= 0 {
				runtime.dispatchChunkLeft = dispatchChunkSize
			}
			runtime.dispatchChunkLeft--
			if runtime.dispatchChunkLeft <= 0 {
				runtime.dispatchRRIdx = (idx + 1) % count
			}
			return true
		default:
		}
	}
	return false
}

// slotIsLive reports whether a relay has carried a datagram recently enough to
// be worth handing another one.
func slotIsLive(slot dispatchSlot, now int64) bool {
	if slot.stream == nil {
		// No liveness to go on; treat it as usable rather than stranding it.
		return true
	}
	return now-slot.stream.lastAliveAt.Load() <= dispatchStaleAfter
}

func (runtime *sessionRuntime) SetProtocolVersion(protocolVersion uint32) {
	_ = protocolVersion
}

func (runtime *sessionRuntime) SetControlHeartbeatSupported(supported bool) {
	if runtime == nil {
		return
	}
	runtime.controlHeartbeatSupported.Store(supported)
}

func (runtime *sessionRuntime) EnsureStream(streamID byte) *streamRuntime {
	if runtime == nil {
		return nil
	}
	runtime.lock.Lock()
	defer runtime.lock.Unlock()

	stream := runtime.streams[streamID]
	if stream == nil {
		now := time.Now().UnixMilli()
		stream = &streamRuntime{
			id:           streamID,
			registeredAt: now,
		}
		// Seed liveness at registration so a relay that has not carried anything
		// yet is not mistaken for one that has died.
		stream.lastAliveAt.Store(now)
		runtime.streams[streamID] = stream
		runtime.reselectLeaderLocked()
	}
	return stream
}

func (runtime *sessionRuntime) RemoveStream(streamID byte) {
	if runtime == nil {
		return
	}
	runtime.lock.Lock()
	defer runtime.lock.Unlock()

	delete(runtime.streams, streamID)
	runtime.reselectLeaderLocked()
}

func (runtime *sessionRuntime) ActiveStreamCount() uint32 {
	if runtime == nil {
		return 0
	}
	runtime.lock.RLock()
	defer runtime.lock.RUnlock()
	return uint32(len(runtime.streams))
}

func (runtime *sessionRuntime) reselectLeaderLocked() {
	var nextLeader byte
	var nextValid bool

	for streamID, stream := range runtime.streams {
		if !stream.dtlsReady.Load() {
			continue
		}
		if !nextValid || streamID < nextLeader {
			nextLeader = streamID
			nextValid = true
		}
	}
	if !nextValid {
		for streamID := range runtime.streams {
			if !nextValid || streamID < nextLeader {
				nextLeader = streamID
				nextValid = true
			}
		}
	}

	runtime.leaderStreamID = nextLeader
	runtime.leaderStreamValid = nextValid
}

func (runtime *sessionRuntime) IsHeartbeatLeader(streamID byte) bool {
	if runtime == nil || !runtime.controlHeartbeatSupported.Load() {
		return false
	}
	runtime.lock.RLock()
	defer runtime.lock.RUnlock()
	return runtime.leaderStreamValid && runtime.leaderStreamID == streamID
}

func (runtime *sessionRuntime) NoteTurnReady(streamID byte) {
	stream := runtime.EnsureStream(streamID)
	if stream == nil {
		return
	}
	stream.turnReady.Store(true)
}

func (runtime *sessionRuntime) NoteDtlsReady(streamID byte) {
	stream := runtime.EnsureStream(streamID)
	if stream == nil {
		return
	}
	stream.dtlsReady.Store(true)
	stream.lastAliveAt.Store(time.Now().UnixMilli())

	runtime.lock.Lock()
	runtime.reselectLeaderLocked()
	runtime.lock.Unlock()
}

func (runtime *sessionRuntime) NoteDtlsAlive(streamID byte) {
	runtime.EnsureStream(streamID).noteAlive()
}

// noteAlive stamps the stream as still carrying traffic.
//
// Reaching the stream through EnsureStream takes the runtime lock, and doing
// that per datagram put every packet of every stream behind one mutex for a
// timestamp. A worker knows its own stream for its whole life, so it resolves
// the handle once and stamps it directly from then on.
func (stream *streamRuntime) noteAlive() {
	if stream == nil {
		return
	}
	stream.lastAliveAt.Store(time.Now().UnixMilli())
}

func (runtime *sessionRuntime) NoteOutbound(streamID byte, bytes int) {
	_ = bytes
	runtime.EnsureStream(streamID)
}

func (runtime *sessionRuntime) NoteInbound(streamID byte, bytes int) {
	_ = bytes
	runtime.NoteDtlsAlive(streamID)
}

// activeInboundDispatcher points at the runtime currently owning inbound
// dispatch, so the socket reader can place a datagram itself instead of waking a
// second goroutine to do it. The reader starts before any runtime exists and
// several runtimes come and go over a session - probe, mainline, mu - so the
// current one is published here rather than captured by the reader.
var activeInboundDispatcher atomic.Pointer[sessionRuntime]

// DispatchInline places pkt on a relay from the calling goroutine. Reports false
// when there is no dispatcher or every relay is busy, which leaves the caller to
// fall back to the queue.
func DispatchInline(pkt *UDPPacket) bool {
	runtime := activeInboundDispatcher.Load()
	if runtime == nil {
		return false
	}
	return runtime.dispatchPacket(pkt)
}
