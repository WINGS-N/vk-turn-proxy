package main

import (
	"net"
	"testing"
)

// BenchmarkDrainQueuedBurst mirrors the Rust probe exactly: fill the socket
// queue, stop the sender, then drain. Comparing this against the probe's
// recvfrom figure prices the Go runtime's receive path against a bare one on the
// same machine and the same kernel.
func BenchmarkDrainQueuedBurst(b *testing.B) {
	receiver, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		b.Fatalf("listen: %v", err)
	}
	defer func() { _ = receiver.Close() }()
	if err := receiver.SetReadBuffer(256 << 20); err != nil {
		b.Fatalf("rcvbuf: %v", err)
	}
	sender, err := net.DialUDP("udp", nil, receiver.LocalAddr().(*net.UDPAddr))
	if err != nil {
		b.Fatalf("dial: %v", err)
	}
	defer func() { _ = sender.Close() }()

	payload := make([]byte, 1400)
	buf := make([]byte, 2048)
	b.ReportAllocs()
	b.SetBytes(1400)
	b.ResetTimer()
	for done := 0; done < b.N; {
		b.StopTimer()
		queued := 0
		for queued < 3640 && done+queued < b.N {
			if _, err := sender.Write(payload); err != nil {
				break
			}
			queued++
		}
		b.StartTimer()
		for i := 0; i < queued; i++ {
			if _, err := receiver.Read(buf); err != nil {
				b.Fatalf("read: %v", err)
			}
		}
		done += queued
	}
	b.StopTimer()
}
