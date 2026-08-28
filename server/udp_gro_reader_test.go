package main

import (
	"bytes"
	"net"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// A coalesced run has to come back out as the datagrams that went in: same
// count, same sizes, same bytes, same order.
func TestGROReaderSplitsCoalescedRun(t *testing.T) {
	receiver, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = receiver.Close() }()
	sender, err := net.DialUDP("udp", nil, receiver.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer func() { _ = sender.Close() }()

	const segment = 1200
	const segments = 6
	raw, err := sender.SyscallConn()
	if err != nil {
		t.Fatalf("syscallconn: %v", err)
	}
	var setErr error
	if err := raw.Control(func(fd uintptr) {
		setErr = unix.SetsockoptInt(int(fd), unix.IPPROTO_UDP, unix.UDP_SEGMENT, segment)
	}); err != nil {
		t.Fatalf("control: %v", err)
	}
	if setErr != nil {
		t.Skipf("UDP_SEGMENT unavailable: %v", setErr)
	}

	batch := make([]byte, segment*segments)
	for i := 0; i < segments; i++ {
		batch[i*segment] = byte(i + 1)
	}
	reader := newGROReader(receiver, 1600)
	if _, err := sender.Write(batch); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := receiver.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("deadline: %v", err)
	}
	for i := 0; i < segments; i++ {
		datagram, err := reader.next()
		if err != nil {
			t.Fatalf("next %d: %v", i, err)
		}
		if len(datagram) != segment {
			t.Fatalf("datagram %d has %d bytes, want %d", i, len(datagram), segment)
		}
		if datagram[0] != byte(i+1) {
			t.Fatalf("datagram %d starts with %d, want %d", i, datagram[0], i+1)
		}
	}
}

// A single datagram, and a short one, must survive whether or not the kernel
// coalesced anything.
func TestGROReaderHandlesLoneDatagram(t *testing.T) {
	receiver, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = receiver.Close() }()
	sender, err := net.DialUDP("udp", nil, receiver.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer func() { _ = sender.Close() }()

	reader := newGROReader(receiver, 1600)
	payload := []byte("a lone datagram")
	if _, err := sender.Write(payload); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := receiver.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("deadline: %v", err)
	}
	got, err := reader.next()
	if err != nil {
		t.Fatalf("next: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("got %q, want %q", got, payload)
	}
	if reader.buffered() != 0 {
		t.Fatalf("buffered = %d, want 0", reader.buffered())
	}
}

// A pipe is not a UDP socket, so the reader must fall back to plain reads.
func TestGROReaderFallsBackForNonUDP(t *testing.T) {
	left, right := net.Pipe()
	t.Cleanup(func() { _ = left.Close(); _ = right.Close() })
	go func() { _, _ = right.Write([]byte("payload")) }()
	reader := newGROReader(left, 1600)
	if reader.coalesce {
		t.Fatal("a pipe must not enable coalescing")
	}
	if err := left.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("deadline: %v", err)
	}
	got, err := reader.next()
	if err != nil {
		t.Fatalf("next: %v", err)
	}
	if string(got) != "payload" {
		t.Fatalf("got %q", got)
	}
}
