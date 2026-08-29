// Package udpoffload drives UDP sockets through the kernel's segmentation
// offload, so a burst costs one syscall instead of one per datagram.
package udpoffload

import (
	"encoding/binary"
	"net"
	"runtime"

	"golang.org/x/sys/unix"
)

// BufferSize holds one coalesced run. The kernel caps a receive batch at 64 KiB.
const BufferSize = 64 << 10

// controlSize is room for the control messages a read may carry; only the
// segment size is of interest, but the buffer has to fit whatever else arrives.
const controlSize = 512

// Reader hands out datagrams from a UDP socket with receive offload enabled.
//
// With UDP_GRO the kernel coalesces a run of same-sized datagrams from one flow
// and delivers the run in a single read, naming the segment size in a control
// message. Callers still want one datagram at a time, so the run is split back
// here - which costs a slice bound next to the syscall per datagram it replaces.
//
// A socket that is not UDP, a kernel without the option, or a platform other
// than Linux all fall back to one read per datagram, so callers need no second
// path.
type Reader struct {
	packet   net.PacketConn
	udp      *net.UDPConn
	buf      []byte
	oob      []byte
	pending  []byte
	sender   net.Addr
	segment  int
	coalesce bool
}

// NewReader enables offload on conn where it can. datagramSize bounds a single
// datagram for the fallback path.
func NewReader(conn net.PacketConn, datagramSize int) *Reader {
	reader := &Reader{packet: conn, buf: make([]byte, datagramSize)}
	udp, ok := conn.(*net.UDPConn)
	if !ok || runtime.GOOS != "linux" {
		return reader
	}
	raw, err := udp.SyscallConn()
	if err != nil {
		return reader
	}
	var setErr error
	if ctlErr := raw.Control(func(fd uintptr) {
		setErr = unix.SetsockoptInt(int(fd), unix.IPPROTO_UDP, unix.UDP_GRO, 1)
	}); ctlErr != nil || setErr != nil {
		return reader
	}
	reader.udp = udp
	reader.coalesce = true
	reader.buf = make([]byte, BufferSize)
	reader.oob = make([]byte, controlSize)
	return reader
}

// Next returns the following datagram and who sent it. The slice stays valid
// until the next call, so a caller that keeps the bytes must copy them.
func (r *Reader) Next() ([]byte, net.Addr, error) {
	if len(r.pending) > 0 {
		return r.take(), r.sender, nil
	}
	if !r.coalesce {
		n, addr, err := r.packet.ReadFrom(r.buf)
		if err != nil {
			return nil, nil, err
		}
		return r.buf[:n], addr, nil
	}
	n, oobn, _, addr, err := r.udp.ReadMsgUDP(r.buf, r.oob)
	if err != nil {
		return nil, nil, err
	}
	r.sender = addr
	r.segment = n
	if size := segmentSize(r.oob[:oobn]); size > 0 {
		r.segment = size
	}
	r.pending = r.buf[:n]
	return r.take(), r.sender, nil
}

// take peels one datagram off the run currently held.
func (r *Reader) take() []byte {
	size := r.segment
	if size <= 0 || size > len(r.pending) {
		size = len(r.pending)
	}
	datagram := r.pending[:size]
	r.pending = r.pending[size:]
	return datagram
}

// Buffered reports how much of a coalesced run is still to be handed out, so a
// caller can skip work that only needs doing once per read.
func (r *Reader) Buffered() int { return len(r.pending) }

// Coalescing reports whether the kernel is merging runs for this socket.
func (r *Reader) Coalescing() bool { return r.coalesce }

// segmentSize reads the size the kernel coalesced with out of the control
// messages. Absent means the read carried a single datagram.
func segmentSize(control []byte) int {
	messages, err := unix.ParseSocketControlMessage(control)
	if err != nil {
		return 0
	}
	for _, message := range messages {
		if message.Header.Level != unix.IPPROTO_UDP || message.Header.Type != unix.UDP_GRO {
			continue
		}
		if len(message.Data) < 2 {
			continue
		}
		// The kernel writes the size in the host's own byte order.
		return int(binary.NativeEndian.Uint16(message.Data))
	}
	return 0
}
