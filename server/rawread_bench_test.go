package main

import (
	"net"
	"syscall"
	"testing"
)

// Go reads a datagram through the runtime's poller, which is what a bare
// recvfrom in another language does not pay for. This drains the same preloaded
// burst straight off the descriptor to price that difference: if the gap to a
// Rust recvfrom is the poller, a raw syscall here should close it.
func BenchmarkDrainRawSyscall(b *testing.B) {
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

	raw, err := receiver.SyscallConn()
	if err != nil {
		b.Fatalf("syscallconn: %v", err)
	}
	var fd int
	if err := raw.Control(func(handle uintptr) { fd = int(handle) }); err != nil {
		b.Fatalf("control: %v", err)
	}

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
			if _, _, err := syscall.Recvfrom(fd, buf, 0); err != nil {
				b.Fatalf("recvfrom: %v", err)
			}
		}
		done += queued
	}
	b.StopTimer()
}
