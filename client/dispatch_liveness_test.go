package main

import (
	"testing"
	"time"
)

// newLivenessRuntime builds a runtime with n relays, each with its own queue.
func newLivenessRuntime(t testing.TB, streams int, depth int) (*sessionRuntime, []chan *UDPPacket) {
	t.Helper()
	runtime := &sessionRuntime{
		streams:        map[byte]*streamRuntime{},
		dispatchActive: true,
	}
	queues := make([]chan *UDPPacket, streams)
	for i := 0; i < streams; i++ {
		id := byte(i)
		runtime.EnsureStream(id)
		queues[i] = make(chan *UDPPacket, depth)
		runtime.BindDispatchChannel(id, queues[i])
	}
	return runtime, queues
}

// A relay that has stopped carrying traffic must be passed over, so the packets
// go to one that is still alive instead of dying in a torn stream's queue.
func TestDispatchSkipsStaleRelay(t *testing.T) {
	runtime, queues := newLivenessRuntime(t, 2, 16)
	stale := runtime.EnsureStream(0)
	live := runtime.EnsureStream(1)

	// Relay 0 went quiet well past the threshold; relay 1 is carrying traffic.
	stale.lastAliveAt.Store(time.Now().UnixMilli() - dispatchStaleAfter - 1000)
	live.lastAliveAt.Store(time.Now().UnixMilli())

	for i := 0; i < 8; i++ {
		if !runtime.dispatchPacket(&UDPPacket{N: 1400}) {
			t.Fatalf("packet %d was not placed", i)
		}
	}
	if got := len(queues[0]); got != 0 {
		t.Fatalf("stale relay received %d packets, want 0", got)
	}
	if got := len(queues[1]); got != 8 {
		t.Fatalf("live relay received %d packets, want 8", got)
	}
}

// When every relay looks quiet - which is also what an idle tunnel looks like -
// the packet still has to go somewhere rather than being dropped.
func TestDispatchFallsBackWhenAllStale(t *testing.T) {
	runtime, queues := newLivenessRuntime(t, 2, 16)
	past := time.Now().UnixMilli() - dispatchStaleAfter - 1000
	runtime.EnsureStream(0).lastAliveAt.Store(past)
	runtime.EnsureStream(1).lastAliveAt.Store(past)

	if !runtime.dispatchPacket(&UDPPacket{N: 1400}) {
		t.Fatal("packet was dropped although relays were available")
	}
	if len(queues[0])+len(queues[1]) != 1 {
		t.Fatalf("packet did not reach a relay: %d + %d", len(queues[0]), len(queues[1]))
	}
}

// A relay that has just been registered has carried nothing yet, and must not be
// mistaken for one that has died.
func TestFreshRelayCountsAsLive(t *testing.T) {
	runtime, queues := newLivenessRuntime(t, 1, 4)
	if !runtime.dispatchPacket(&UDPPacket{N: 1400}) {
		t.Fatal("packet was not placed on a freshly registered relay")
	}
	if len(queues[0]) != 1 {
		t.Fatalf("fresh relay received %d packets, want 1", len(queues[0]))
	}
}

// A full queue still has to fall through to the next relay, as before.
func TestDispatchSkipsFullRelay(t *testing.T) {
	runtime, queues := newLivenessRuntime(t, 2, 1)
	now := time.Now().UnixMilli()
	runtime.EnsureStream(0).lastAliveAt.Store(now)
	runtime.EnsureStream(1).lastAliveAt.Store(now)

	queues[0] <- &UDPPacket{N: 1} // relay 0 is full
	if !runtime.dispatchPacket(&UDPPacket{N: 1400}) {
		t.Fatal("packet was dropped although relay 1 was free")
	}
	if len(queues[1]) != 1 {
		t.Fatalf("relay 1 received %d packets, want 1", len(queues[1]))
	}
}
