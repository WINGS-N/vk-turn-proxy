package main

import (
	"net"
	"runtime"
	"time"

	"golang.org/x/sys/unix"
)

// gsoMaxSegments is the kernel's ceiling on segments per UDP_SEGMENT write.
const gsoMaxSegments = 64

// gsoMaxPayload keeps a batch inside one UDP datagram's worth of payload.
const gsoMaxPayload = 60000

// udpGSOWriter forwards datagrams to a connected UDP socket, coalescing a run of
// them into a single write and letting the kernel split it back apart.
//
// UDP segmentation offload only accepts a batch whose segments are all the same
// size, except the last, so only a run of equal-length datagrams can be merged.
// That matches the traffic worth optimising: bulk transfer through the tunnel is
// a stream of MTU-sized packets, while mixed small traffic - where a batch would
// not form anyway - is exactly the traffic that is not throughput-bound. A
// differently sized datagram flushes what is pending and starts a new run.
//
// Falls back to one write per datagram when the platform or socket has no
// UDP_SEGMENT, so callers need no separate path.
type udpGSOWriter struct {
	conn     net.Conn
	udp      *net.UDPConn
	buf      []byte
	segment  int
	count    int
	enabled  bool
	armedFor int
}

func newUDPGSOWriter(conn net.Conn, maxDatagram int) *udpGSOWriter {
	writer := &udpGSOWriter{conn: conn}
	udp, ok := conn.(*net.UDPConn)
	if !ok || runtime.GOOS != "linux" {
		return writer
	}
	writer.udp = udp
	writer.enabled = true
	writer.buf = make([]byte, 0, maxDatagram*gsoMaxSegments)
	return writer
}

// queue adds one datagram. It may write to the socket, when the pending run is
// full or the new datagram does not fit the run.
func (w *udpGSOWriter) queue(datagram []byte) error {
	if !w.enabled {
		_, err := w.conn.Write(datagram)
		return err
	}
	if w.count > 0 && (len(datagram) != w.segment || w.count >= gsoMaxSegments ||
		len(w.buf)+len(datagram) > gsoMaxPayload) {
		if err := w.flush(); err != nil {
			return err
		}
	}
	if w.count == 0 {
		w.segment = len(datagram)
	}
	w.buf = append(w.buf, datagram...)
	w.count++
	return nil
}

// flush writes whatever is pending. A single datagram goes out as a plain write:
// arming segmentation for it would cost a setsockopt and save nothing.
func (w *udpGSOWriter) flush() error {
	if w.count == 0 {
		return nil
	}
	payload := w.buf
	segments := w.count
	segment := w.segment
	w.buf = w.buf[:0]
	w.count = 0

	if segments == 1 {
		_, err := w.conn.Write(payload)
		return err
	}
	if err := w.armSegmentation(segment); err != nil {
		// Segmentation is unavailable after all; send the run one by one and
		// stop trying for the rest of this connection.
		w.enabled = false
		for offset := 0; offset < len(payload); offset += segment {
			end := offset + segment
			if end > len(payload) {
				end = len(payload)
			}
			if _, writeErr := w.conn.Write(payload[offset:end]); writeErr != nil {
				return writeErr
			}
		}
		return nil
	}
	_, err := w.conn.Write(payload)
	return err
}

// armSegmentation sets the segment size on the socket, skipping the syscall when
// it already holds the value a previous batch installed.
func (w *udpGSOWriter) armSegmentation(segment int) error {
	if w.armedFor == segment {
		return nil
	}
	raw, err := w.udp.SyscallConn()
	if err != nil {
		return err
	}
	var setErr error
	if ctlErr := raw.Control(func(fd uintptr) {
		setErr = unix.SetsockoptInt(int(fd), unix.IPPROTO_UDP, unix.UDP_SEGMENT, segment)
	}); ctlErr != nil {
		return ctlErr
	}
	if setErr != nil {
		return setErr
	}
	w.armedFor = segment
	return nil
}

// pending reports how many datagrams are held back waiting for a flush.
func (w *udpGSOWriter) pending() int { return w.count }

// gatherProbeInterval is how often an idle stream checks whether a burst has
// started. Probing costs two deadline writes and one failed read, so at low rate
// it is sampled rather than done on every datagram; once a probe finds a second
// datagram the stream keeps probing until one comes back empty.
const gatherProbeInterval = 16

// readGatherer decides when it is worth asking the source for another datagram
// before flushing what is already queued.
//
// The relay reads one datagram at a time, so segmentation would never see a run
// to merge unless something looks ahead. Looking ahead is only free when a burst
// is actually in flight: otherwise the probe pays for a read that returns
// nothing. The sampling keeps that cost off an idle stream while still noticing
// when the stream turns busy.
type readGatherer struct {
	bursting  bool
	sinceLast int
}

// shouldProbe reports whether to look for another datagram right now.
func (g *readGatherer) shouldProbe() bool {
	if g.bursting {
		return true
	}
	g.sinceLast++
	if g.sinceLast < gatherProbeInterval {
		return false
	}
	g.sinceLast = 0
	return true
}

// observe records what the probe found, so a burst keeps the look-ahead on and
// a quiet stream turns it back off.
func (g *readGatherer) observe(found bool) {
	g.bursting = found
	if found {
		g.sinceLast = 0
	}
}

// readIfReady takes one more datagram only if the source already has it. The
// deadline is set in the past so a read that would block returns immediately,
// and it is cleared afterwards so the caller's own idle deadline still governs
// the next blocking read.
func readIfReady(conn net.Conn, buf []byte) ([]byte, bool) {
	if err := conn.SetReadDeadline(time.Now()); err != nil {
		return nil, false
	}
	n, err := conn.Read(buf)
	if clearErr := conn.SetReadDeadline(time.Time{}); clearErr != nil {
		return nil, false
	}
	if err != nil || n == 0 {
		return nil, false
	}
	return buf[:n], true
}

// gatherBurst pulls whatever datagrams the source already has and feeds them to
// handle, so the writer gets a run to segment instead of one datagram at a time.
// It only looks ahead while a burst is running; probing clears the read deadline,
// so the caller's idle deadline is marked for re-arming.
func gatherBurst(
	conn net.Conn,
	buf []byte,
	gather *readGatherer,
	readDeadline *slidingDeadline,
	handle func([]byte) error,
) error {
	for gather.shouldProbe() {
		extra, found := readIfReady(conn, buf)
		gather.observe(found)
		readDeadline.reset()
		if !found {
			return nil
		}
		if err := handle(extra); err != nil {
			return err
		}
	}
	return nil
}
