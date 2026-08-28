package main

import "testing"

// The inbound path hands every datagram to a worker goroutine through a buffered
// channel. These price that hop against doing the work on the reading goroutine.

func BenchmarkChannelHandoff(b *testing.B) {
	queue := make(chan *UDPPacket, inboundPacketQueueSize)
	done := make(chan struct{})
	var seen int
	go func() {
		defer close(done)
		for pkt := range queue {
			seen += pkt.N
		}
	}()
	pkt := &UDPPacket{N: 1400}
	b.ReportAllocs()
	b.SetBytes(1400)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		queue <- pkt
	}
	b.StopTimer()
	close(queue)
	<-done
	_ = seen
}

// The same work with no goroutine in between.
func BenchmarkInlineHandoff(b *testing.B) {
	var seen int
	pkt := &UDPPacket{N: 1400}
	b.ReportAllocs()
	b.SetBytes(1400)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		seen += pkt.N
	}
	b.StopTimer()
	_ = seen
}

// A pool round trip, which the inbound path also pays per datagram.
func BenchmarkPacketPoolRoundTrip(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		pkt, ok := packetPool.Get().(*UDPPacket)
		if !ok {
			b.Fatal("pool returned an unexpected type")
		}
		packetPool.Put(pkt)
	}
}
