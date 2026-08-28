package main

import (
	"net"
	"testing"

	"golang.org/x/sys/unix"
)

// UDP_GRO is the receive side of segmentation offload: the kernel coalesces a
// run of same-sized datagrams from one flow and hands them over in a single
// read, with a control message naming the segment size. These price a drain with
// it against the same drain without.

func groPair(b *testing.B, gro bool) (*net.UDPConn, *net.UDPConn) {
	b.Helper()
	receiver, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		b.Fatalf("listen: %v", err)
	}
	b.Cleanup(func() { _ = receiver.Close() })
	if err := receiver.SetReadBuffer(256 << 20); err != nil {
		b.Fatalf("rcvbuf: %v", err)
	}
	if gro {
		raw, ctlErr := receiver.SyscallConn()
		if ctlErr != nil {
			b.Fatalf("syscallconn: %v", ctlErr)
		}
		var setErr error
		if err := raw.Control(func(fd uintptr) {
			setErr = unix.SetsockoptInt(int(fd), unix.IPPROTO_UDP, unix.UDP_GRO, 1)
		}); err != nil {
			b.Fatalf("control: %v", err)
		}
		if setErr != nil {
			b.Skipf("UDP_GRO unavailable: %v", setErr)
		}
	}
	sender, err := net.DialUDP("udp", nil, receiver.LocalAddr().(*net.UDPAddr))
	if err != nil {
		b.Fatalf("dial: %v", err)
	}
	b.Cleanup(func() { _ = sender.Close() })
	if err := sender.SetWriteBuffer(256 << 20); err != nil {
		b.Fatalf("sndbuf: %v", err)
	}
	// Send the burst segmented, which is what gives GRO something to coalesce.
	raw, err := sender.SyscallConn()
	if err != nil {
		b.Fatalf("syscallconn: %v", err)
	}
	if err := raw.Control(func(fd uintptr) {
		_ = unix.SetsockoptInt(int(fd), unix.IPPROTO_UDP, unix.UDP_SEGMENT, 1400)
	}); err != nil {
		b.Fatalf("control: %v", err)
	}
	return receiver, sender
}

func benchGRO(b *testing.B, gro bool) {
	b.Helper()
	receiver, sender := groPair(b, gro)
	const segments = 32
	batch := make([]byte, 1400*segments)
	buf := make([]byte, 128<<10)
	oob := make([]byte, 1024)

	b.ReportAllocs()
	b.SetBytes(1400)
	b.ResetTimer()
	for done := 0; done < b.N; {
		b.StopTimer()
		queued := 0
		for queued+segments <= 3200 && done+queued < b.N {
			if _, err := sender.Write(batch); err != nil {
				break
			}
			queued += segments
		}
		if queued == 0 {
			b.StopTimer()
			break
		}
		b.StartTimer()
		got := 0
		for got < queued {
			n, _, _, _, err := receiver.ReadMsgUDP(buf, oob)
			if err != nil {
				b.Fatalf("readmsg: %v", err)
			}
			// Without GRO one read is one datagram; with it, one read can carry a
			// whole run and the count comes from how much arrived.
			if n <= 1400 {
				got++
			} else {
				got += (n + 1399) / 1400
			}
		}
		done += got
	}
	b.StopTimer()
}

func BenchmarkReceivePlain(b *testing.B) { benchGRO(b, false) }

func BenchmarkReceiveGRO(b *testing.B) { benchGRO(b, true) }
