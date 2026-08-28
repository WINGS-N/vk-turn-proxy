package main

import (
	"net"
	"testing"
	"time"
)

func gsoLoopback(t testing.TB) (*net.UDPConn, *net.UDPConn) {
	t.Helper()
	peer, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = peer.Close() })
	if err := peer.SetReadBuffer(32 << 20); err != nil {
		t.Fatalf("rcvbuf: %v", err)
	}
	sender, err := net.DialUDP("udp", nil, peer.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { _ = sender.Close() })
	if err := sender.SetWriteBuffer(32 << 20); err != nil {
		t.Fatalf("sndbuf: %v", err)
	}
	return sender, peer
}

// A run of equal-sized datagrams must arrive as that many separate datagrams,
// each byte-identical to what was queued.
func TestGSOWriterSplitsBackIntoDatagrams(t *testing.T) {
	sender, peer := gsoLoopback(t)
	writer := newUDPGSOWriter(sender, 1600)
	const count = 8
	for i := 0; i < count; i++ {
		datagram := make([]byte, 1400)
		datagram[0] = byte(i)
		if err := writer.queue(datagram); err != nil {
			t.Fatalf("queue %d: %v", i, err)
		}
	}
	if err := writer.flush(); err != nil {
		t.Fatalf("flush: %v", err)
	}
	buf := make([]byte, 4096)
	for i := 0; i < count; i++ {
		if err := peer.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
			t.Fatalf("deadline: %v", err)
		}
		n, err := peer.Read(buf)
		if err != nil {
			t.Fatalf("read %d: %v", i, err)
		}
		if n != 1400 || buf[0] != byte(i) {
			t.Fatalf("datagram %d: len=%d marker=%d", i, n, buf[0])
		}
	}
}

// A different length has to flush the pending run, so ordering and framing hold
// even when sizes change mid-stream.
func TestGSOWriterFlushesOnSizeChange(t *testing.T) {
	sender, peer := gsoLoopback(t)
	writer := newUDPGSOWriter(sender, 1600)
	sizes := []int{1400, 1400, 300, 1400}
	for i, size := range sizes {
		datagram := make([]byte, size)
		datagram[0] = byte(i)
		if err := writer.queue(datagram); err != nil {
			t.Fatalf("queue %d: %v", i, err)
		}
	}
	if err := writer.flush(); err != nil {
		t.Fatalf("flush: %v", err)
	}
	buf := make([]byte, 4096)
	for i, size := range sizes {
		if err := peer.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
			t.Fatalf("deadline: %v", err)
		}
		n, err := peer.Read(buf)
		if err != nil {
			t.Fatalf("read %d: %v", i, err)
		}
		if n != size || buf[0] != byte(i) {
			t.Fatalf("datagram %d: len=%d want %d, marker=%d", i, n, size, buf[0])
		}
	}
}

func TestGSOWriterFallsBackForNonUDP(t *testing.T) {
	left, right := net.Pipe()
	t.Cleanup(func() { _ = left.Close(); _ = right.Close() })
	received := make(chan int, 1)
	go func() {
		buf := make([]byte, 64)
		n, _ := right.Read(buf)
		received <- n
	}()
	writer := newUDPGSOWriter(left, 1600)
	if writer.enabled {
		t.Fatal("a pipe must not enable segmentation")
	}
	if err := writer.queue([]byte("payload")); err != nil {
		t.Fatalf("queue: %v", err)
	}
	if n := <-received; n != 7 {
		t.Fatalf("got %d bytes", n)
	}
}

func benchGSO(b *testing.B, batched bool, size int) {
	b.Helper()
	sender, peer := gsoLoopback(b)
	stop := make(chan struct{})
	go func() {
		buf := make([]byte, 65535)
		for {
			select {
			case <-stop:
				return
			default:
			}
			_ = peer.SetReadDeadline(time.Now().Add(time.Second))
			if _, err := peer.Read(buf); err != nil {
				return
			}
		}
	}()
	defer close(stop)

	writer := newUDPGSOWriter(sender, 1600)
	if !batched {
		writer.enabled = false
	}
	datagram := make([]byte, size)
	b.ReportAllocs()
	b.SetBytes(int64(size))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := writer.queue(datagram); err != nil {
			b.Fatalf("queue: %v", err)
		}
		if writer.pending() >= gsoMaxSegments {
			if err := writer.flush(); err != nil {
				b.Fatalf("flush: %v", err)
			}
		}
	}
	_ = writer.flush()
	b.StopTimer()
}

func BenchmarkGSOWriterPerDatagram(b *testing.B) { benchGSO(b, false, 1400) }

func BenchmarkGSOWriterBatched(b *testing.B) { benchGSO(b, true, 1400) }
