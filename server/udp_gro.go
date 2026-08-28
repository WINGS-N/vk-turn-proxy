package main

import (
	"encoding/binary"
	"net"
	"runtime"

	"golang.org/x/sys/unix"
)

// groBufferSize holds one coalesced run. The kernel caps a GRO batch at 64 KiB,
// so a read never needs more than this.
const groBufferSize = 64 << 10

// groControlSize is room for the control messages a read may carry; only the
// segment size is of interest, but the buffer has to fit whatever else arrives.
const groControlSize = 512

// groReader reads datagrams from a connected UDP socket with receive
// segmentation offload.
//
// With UDP_GRO the kernel coalesces a run of same-sized datagrams from one flow
// and hands the whole run over in a single read, naming the segment size in a
// control message. The relay still forwards one datagram at a time, so the run
// is split back here - but the split costs nothing next to the syscall per
// datagram it replaces.
//
// Without the option, or on a socket that is not UDP, every read returns exactly
// what arrived and the caller sees no difference.
type groReader struct {
	conn     net.Conn
	udp      *net.UDPConn
	buf      []byte
	oob      []byte
	pending  []byte
	segment  int
	coalesce bool
}

func newGROReader(conn net.Conn, maxDatagram int) *groReader {
	reader := &groReader{conn: conn, buf: make([]byte, maxDatagram)}
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
	reader.buf = make([]byte, groBufferSize)
	reader.oob = make([]byte, groControlSize)
	return reader
}

// next returns the following datagram. The slice stays valid until the next
// call, which is all the relay needs: it forwards and moves on.
func (r *groReader) next() ([]byte, error) {
	if len(r.pending) > 0 {
		return r.take(), nil
	}
	if !r.coalesce {
		n, err := r.conn.Read(r.buf)
		if err != nil {
			return nil, err
		}
		return r.buf[:n], nil
	}
	n, oobn, _, _, err := r.udp.ReadMsgUDP(r.buf, r.oob)
	if err != nil {
		return nil, err
	}
	r.segment = n
	if size := segmentSize(r.oob[:oobn]); size > 0 {
		r.segment = size
	}
	r.pending = r.buf[:n]
	return r.take(), nil
}

// take peels one datagram off the run currently held.
func (r *groReader) take() []byte {
	size := r.segment
	if size <= 0 || size > len(r.pending) {
		size = len(r.pending)
	}
	datagram := r.pending[:size]
	r.pending = r.pending[size:]
	return datagram
}

// buffered reports how much of a coalesced run is still to be handed out, so a
// caller can skip work that only needs doing once per read.
func (r *groReader) buffered() int { return len(r.pending) }

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
