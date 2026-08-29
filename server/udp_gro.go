package main

import (
	"net"

	"github.com/cacggghp/vk-turn-proxy/internal/udpoffload"
)

// upstreamDatagramSize bounds one datagram on the fallback path. The relay never
// carries more than the tunnel MTU plus TURN and WRAP framing.
const upstreamDatagramSize = 1600

// upstreamReader reads the upstream socket with receive offload.
//
// The upstream side is a connected UDP socket, so the kernel will merge a run of
// same-sized datagrams into one read and say how big each was. The relay still
// forwards them one at a time; splitting the run back apart costs a slice bound
// against a syscall saved per datagram.
type upstreamReader struct {
	reader *udpoffload.Reader
}

func newUpstreamReader(conn net.Conn) *upstreamReader {
	packet, ok := conn.(net.PacketConn)
	if !ok {
		// Not a packet socket - a pipe in tests, or a stream conn - so read it
		// directly and let the caller see one read per call.
		return &upstreamReader{reader: nil}
	}
	return &upstreamReader{reader: udpoffload.NewReader(packet, upstreamDatagramSize)}
}

// next returns the following datagram, valid until the call after it.
func (r *upstreamReader) next(conn net.Conn, scratch []byte) ([]byte, error) {
	if r.reader == nil {
		n, err := conn.Read(scratch)
		if err != nil {
			return nil, err
		}
		return scratch[:n], nil
	}
	datagram, _, err := r.reader.Next()
	return datagram, err
}

// buffered reports how much of a coalesced run is still to be handed out.
func (r *upstreamReader) buffered() int {
	if r.reader == nil {
		return 0
	}
	return r.reader.Buffered()
}

// coalescing reports whether the kernel is merging runs for this socket.
func (r *upstreamReader) coalescing() bool {
	return r.reader != nil && r.reader.Coalescing()
}
