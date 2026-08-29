package udpoffload

import (
	"bytes"
	"net"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func loopback(t *testing.T) (*net.UDPConn, *net.UDPConn) {
	t.Helper()
	receiver, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = receiver.Close() })
	sender, err := net.DialUDP("udp", nil, receiver.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { _ = sender.Close() })
	return receiver, sender
}

// A coalesced run has to come back out as the datagrams that went in: same
// count, same sizes, same bytes, same order.
func TestReaderSplitsCoalescedRun(t *testing.T) {
	receiver, sender := loopback(t)
	const segment = 1200
	const segments = 6
	raw, err := sender.SyscallConn()
	if err != nil {
		t.Fatalf("syscallconn: %v", err)
	}
	var setErr error
	if ctlErr := raw.Control(func(fd uintptr) {
		setErr = unix.SetsockoptInt(int(fd), unix.IPPROTO_UDP, unix.UDP_SEGMENT, segment)
	}); ctlErr != nil {
		t.Fatalf("control: %v", ctlErr)
	}
	if setErr != nil {
		t.Skipf("UDP_SEGMENT unavailable: %v", setErr)
	}

	batch := make([]byte, segment*segments)
	for i := 0; i < segments; i++ {
		batch[i*segment] = byte(i + 1)
	}
	reader := NewReader(receiver, 2048)
	if _, err := sender.Write(batch); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := receiver.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("deadline: %v", err)
	}
	for i := 0; i < segments; i++ {
		datagram, addr, err := reader.Next()
		if err != nil {
			t.Fatalf("next %d: %v", i, err)
		}
		if addr == nil {
			t.Fatalf("datagram %d has no sender", i)
		}
		if len(datagram) != segment {
			t.Fatalf("datagram %d has %d bytes, want %d", i, len(datagram), segment)
		}
		if datagram[0] != byte(i+1) {
			t.Fatalf("datagram %d starts with %d, want %d", i, datagram[0], i+1)
		}
	}
	if reader.Buffered() != 0 {
		t.Fatalf("buffered = %d after draining the run", reader.Buffered())
	}
}

// A short final segment is legal: the kernel coalesces same-sized datagrams but
// the last one of a run may be smaller.
func TestReaderHandlesShortFinalSegment(t *testing.T) {
	receiver, sender := loopback(t)
	const segment = 1000
	raw, err := sender.SyscallConn()
	if err != nil {
		t.Fatalf("syscallconn: %v", err)
	}
	var setErr error
	if ctlErr := raw.Control(func(fd uintptr) {
		setErr = unix.SetsockoptInt(int(fd), unix.IPPROTO_UDP, unix.UDP_SEGMENT, segment)
	}); ctlErr != nil {
		t.Fatalf("control: %v", ctlErr)
	}
	if setErr != nil {
		t.Skipf("UDP_SEGMENT unavailable: %v", setErr)
	}

	batch := make([]byte, segment*2+300)
	reader := NewReader(receiver, 2048)
	if _, err := sender.Write(batch); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := receiver.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("deadline: %v", err)
	}
	sizes := []int{}
	for i := 0; i < 3; i++ {
		datagram, _, err := reader.Next()
		if err != nil {
			t.Fatalf("next %d: %v", i, err)
		}
		sizes = append(sizes, len(datagram))
	}
	want := []int{segment, segment, 300}
	for i := range want {
		if sizes[i] != want[i] {
			t.Fatalf("segment sizes %v, want %v", sizes, want)
		}
	}
}

func TestReaderPassesLoneDatagramThrough(t *testing.T) {
	receiver, sender := loopback(t)
	reader := NewReader(receiver, 2048)
	payload := []byte("a lone datagram")
	if _, err := sender.Write(payload); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := receiver.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("deadline: %v", err)
	}
	got, _, err := reader.Next()
	if err != nil {
		t.Fatalf("next: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("got %q, want %q", got, payload)
	}
}
