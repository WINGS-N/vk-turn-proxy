package main

import (
	"context"
	"testing"
)

// newBenchRuntime builds a runtime with one relay slot whose sender is drained,
// so dispatch always finds somewhere to put the packet.
func newBenchRuntime(b *testing.B) (*sessionRuntime, func()) {
	b.Helper()
	runtime := &sessionRuntime{dispatchActive: true}
	sendCh := make(chan *UDPPacket, 1024)
	runtime.dispatchSlots = append(runtime.dispatchSlots, dispatchSlot{streamID: 0, sendCh: sendCh})
	done := make(chan struct{})
	go func() {
		defer close(done)
		for pkt := range sendCh {
			packetPool.Put(pkt)
		}
	}()
	return runtime, func() {
		close(sendCh)
		<-done
	}
}

// The path as it was: reader hands the datagram to a dispatch goroutine, which
// then places it on a relay.
func BenchmarkDispatchViaQueue(b *testing.B) {
	runtime, stop := newBenchRuntime(b)
	defer stop()
	queue := make(chan *UDPPacket, inboundPacketQueueSize)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	drained := make(chan struct{})
	go func() {
		defer close(drained)
		runtime.RunInboundDispatchLoop(ctx, queue)
	}()

	b.ReportAllocs()
	b.SetBytes(1400)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		pkt, ok := packetPool.Get().(*UDPPacket)
		if !ok {
			b.Fatal("pool returned an unexpected type")
		}
		pkt.N = 1400
		queue <- pkt
	}
	b.StopTimer()
	cancel()
	<-drained
}

// The path now: the reading goroutine places the datagram itself.
func BenchmarkDispatchInline(b *testing.B) {
	runtime, stop := newBenchRuntime(b)
	defer stop()
	activeInboundDispatcher.Store(runtime)
	defer activeInboundDispatcher.CompareAndSwap(runtime, nil)

	b.ReportAllocs()
	b.SetBytes(1400)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		pkt, ok := packetPool.Get().(*UDPPacket)
		if !ok {
			b.Fatal("pool returned an unexpected type")
		}
		pkt.N = 1400
		if !DispatchInline(pkt) {
			packetPool.Put(pkt)
		}
	}
	b.StopTimer()
}
