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

	dispatchMu     sync.Mutex
	dispatchSlots  []dispatchSlot
	dispatchRRIdx  int
	dispatchActive bool

	credsManager *groupedCredsManager
}

type dispatchSlot struct {
	streamID byte
	sendCh   chan *UDPPacket
}

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
	runtime.dispatchSlots = append(runtime.dispatchSlots, dispatchSlot{streamID: streamID, sendCh: packets})
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
			return
		}
	}
}

func (runtime *sessionRuntime) RunInboundDispatchLoop(ctx context.Context, inboundChan <-chan *UDPPacket) {
	if runtime == nil {
		return
	}
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
	start := runtime.dispatchRRIdx % count
	for i := 0; i < count; i++ {
		idx := (start + i) % count
		select {
		case runtime.dispatchSlots[idx].sendCh <- pkt:
			runtime.dispatchRRIdx = (idx + 1) % count
			return true
		default:
		}
	}
	return false
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
		stream = &streamRuntime{
			id:           streamID,
			registeredAt: time.Now().UnixMilli(),
		}
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
	stream := runtime.EnsureStream(streamID)
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
