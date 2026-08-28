package main

import (
	"net"
	"testing"
	"time"
)

func benchDeadlineConn(b *testing.B) *net.UDPConn {
	b.Helper()
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		b.Fatalf("listen: %v", err)
	}
	b.Cleanup(func() { _ = conn.Close() })
	return conn
}

// What the relay loops used to do: rearm the idle deadline on every datagram.
func BenchmarkDeadlinePerPacket(b *testing.B) {
	conn := benchDeadlineConn(b)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := conn.SetReadDeadline(time.Now().Add(30 * time.Minute)); err != nil {
			b.Fatal(err)
		}
	}
}

// What they do now: move it only when it is close to expiring.
func BenchmarkDeadlineSliding(b *testing.B) {
	conn := benchDeadlineConn(b)
	deadline := newSlidingDeadline(30 * time.Minute)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := deadline.apply(conn.SetReadDeadline); err != nil {
			b.Fatal(err)
		}
	}
}
