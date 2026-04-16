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
		mode:          mode,
		statusEnabled: statusEnabled,
		streams:       make(map[byte]*streamRuntime),
	}
}

func (runtime *sessionRuntime) DispatchesInbound() bool {
	return false
}

func (runtime *sessionRuntime) BindDispatchChannel(streamID byte, packets chan *UDPPacket) {
	_ = streamID
	_ = packets
}

func (runtime *sessionRuntime) UnbindDispatchChannel(streamID byte) {
	_ = streamID
}

func (runtime *sessionRuntime) RunInboundDispatchLoop(ctx context.Context, inboundChan <-chan *UDPPacket) {
	_ = ctx
	_ = inboundChan
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
