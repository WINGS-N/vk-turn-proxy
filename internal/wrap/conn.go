package wrap

import (
	"log"
	"net"
	"sync"
	"sync/atomic"

	dtlsnet "github.com/pion/dtls/v3/pkg/net"
)

// readBufSize bounds how much we read from the underlying conn per packet.
// 65535 covers a max-sized UDP datagram; the actual budget at runtime is
// also constrained by socket-level limits (SO_RCVBUF, TURN ChannelData
// framing, etc.).
const readBufSize = 65535

// dtlsRecordTypeMin / dtlsRecordTypeMax bracket the DTLS ContentType range
// (RFC 9147 §4.1): change_cipher_spec=20, alert=21, handshake=22,
// application_data=23, heartbeat=24, ack=26. We use the first wire byte
// to disambiguate raw DTLS records (in this range) from SRTP-mimicry
// packets (first byte == rtpVersion = 0x80).
const (
	dtlsRecordTypeMin = 0x14 // 20 (change_cipher_spec)
	dtlsRecordTypeMax = 0x1A // 26 (ack)
)

// StatefulConn is a net.PacketConn that can dynamically switch between
// pass-through (raw bytes flow) and wrapped (SRTP-mimicry AEAD) send
// modes at runtime via Enable/Disable.
//
// The receive path auto-detects per packet by the first wire byte:
//   - 0x80  → SRTP-mimicry, attempt Open via the installed cipher;
//   - 0x14..0x1A → raw DTLS record, pass through to the upper layer;
//   - anything else → pass through (treated as opaque noise the upper
//     layer will reject).
//
// Auto-detect on receive makes the Enable/Disable transitions race-free:
// peers can switch send modes without coordinating exact packet
// boundaries — whatever arrives is decoded based on its own bytes, not
// on the receiver's current send state.
type StatefulConn struct {
	net.PacketConn
	cipher atomic.Pointer[Cipher]
}

// NewStateful wraps inner. Starts in pass-through mode (no wrap on send,
// auto-detect on receive but no cipher yet so SRTP-shaped packets are
// dropped). Use Enable to switch to wrapped send.
func NewStateful(inner net.PacketConn) *StatefulConn {
	return &StatefulConn{PacketConn: inner}
}

// Enable switches send to wrapped mode using the given Cipher. Subsequent
// WriteTo calls Seal payloads with c. Concurrent-safe.
func (s *StatefulConn) Enable(c Cipher) {
	s.cipher.Store(&c)
}

// Disable returns send to pass-through mode and forgets the cipher.
// After Disable, incoming SRTP-shaped packets are dropped (no cipher to
// Open them with). In typical use we never call Disable on an
// established session — the wrap state is set once via Enable.
func (s *StatefulConn) Disable() {
	s.cipher.Store(nil)
}

// CipherEnabled reports whether send-side wrapping is currently active.
func (s *StatefulConn) CipherEnabled() bool {
	return s.cipher.Load() != nil
}

// WriteTo seals (if a cipher is installed) and writes the datagram. The
// returned byte count reflects the plaintext length so callers receive a
// value consistent with their unwrapped view.
func (s *StatefulConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	cp := s.cipher.Load()
	if cp == nil {
		return s.PacketConn.WriteTo(p, addr)
	}
	sealed, err := (*cp).Seal(p)
	if err != nil {
		return 0, err
	}
	if _, err := s.PacketConn.WriteTo(sealed, addr); err != nil {
		return 0, err
	}
	return len(p), nil
}

// ReadFrom returns the next datagram, auto-detecting raw vs SRTP-wrapped
// by the first wire byte. Wrapped packets with a failing AEAD Open are
// dropped silently and the loop reads the next one; raw packets are
// passed through unchanged.
func (s *StatefulConn) ReadFrom(p []byte) (int, net.Addr, error) {
	buf := make([]byte, readBufSize)
	for {
		n, addr, err := s.PacketConn.ReadFrom(buf)
		if err != nil {
			return 0, addr, err
		}
		if n == 0 {
			return 0, addr, nil
		}
		if buf[0] == rtpVersion {
			cp := s.cipher.Load()
			if cp == nil {
				log.Printf("wrap: drop SRTP-shaped packet from %s (%d bytes): no cipher installed", addr, n)
				continue
			}
			plain, openErr := (*cp).Open(buf[:n])
			if openErr != nil {
				log.Printf("wrap: drop SRTP-shaped packet from %s (%d bytes): %s", addr, n, openErr)
				continue
			}
			return copy(p, plain), addr, nil
		}
		// Raw DTLS record or other unrecognized — pass through. The
		// upper layer (DTLS) handles its own validation.
		_ = dtlsRecordTypeMin // referenced for documentation; allowed range is buf[0] ∈ [Min..Max]
		_ = dtlsRecordTypeMax
		return copy(p, buf[:n]), addr, nil
	}
}

// PacketConn wraps a net.PacketConn so that every datagram is encrypted
// on send and decrypted on receive using the supplied per-conn Cipher.
//
// This is the static variant: send-mode is fixed at construction time
// (always wrapped). Use NewStateful + Enable for runtime mode switching.
//
// Returning the original conn verbatim when cipher is nil keeps
// call-sites symmetric for the "no obfuscation negotiated" path.
func PacketConn(inner net.PacketConn, c Cipher) net.PacketConn {
	if c == nil {
		return inner
	}
	s := NewStateful(inner)
	s.Enable(c)
	return s
}

// Listener is a dtls.PacketListener that wraps every accepted PacketConn
// as a StatefulConn (initially in pass-through). It also tracks the
// per-addr StatefulConn so that an upper layer (mu/v1 SessionHello
// handler) can Enable the wrap cipher once it has negotiated one with
// the client. Without this side-channel, the *StatefulConn instance is
// hidden inside pion's *dtls.Listener after the handshake and there is
// no way to flip it from above.
type Listener struct {
	inner dtlsnet.PacketListener
	mu    sync.Mutex
	conns map[string]*StatefulConn
}

// NewListener constructs a Listener around an existing
// dtlsnet.PacketListener. The returned value satisfies
// dtlsnet.PacketListener so it can be passed straight to
// dtls.NewListener / dtls.NewListenerWithOptions.
func NewListener(inner dtlsnet.PacketListener) *Listener {
	return &Listener{inner: inner, conns: make(map[string]*StatefulConn)}
}

// Accept satisfies dtlsnet.PacketListener. The returned PacketConn is
// the *StatefulConn for this remote; the same value is retrievable via
// Lookup(addr).
func (l *Listener) Accept() (net.PacketConn, net.Addr, error) {
	pc, addr, err := l.inner.Accept()
	if err != nil {
		return pc, addr, err
	}
	s := NewStateful(pc)
	if addr != nil {
		l.mu.Lock()
		l.conns[addr.String()] = s
		l.mu.Unlock()
	}
	return s, addr, nil
}

// Close closes the underlying listener and forgets all tracked
// StatefulConns. Already-accepted conns are not closed (callers own
// them).
func (l *Listener) Close() error {
	l.mu.Lock()
	l.conns = make(map[string]*StatefulConn)
	l.mu.Unlock()
	return l.inner.Close()
}

// Addr returns the local listening address.
func (l *Listener) Addr() net.Addr { return l.inner.Addr() }

// Lookup returns the StatefulConn associated with addr (the peer's
// remote address as observed at Accept time), or nil if no such conn
// has been accepted or Forget has been called.
func (l *Listener) Lookup(addr net.Addr) *StatefulConn {
	if addr == nil {
		return nil
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.conns[addr.String()]
}

// Forget releases the per-addr tracking entry. Callers should invoke
// this when the corresponding DTLS conn is closed to keep the map bounded.
func (l *Listener) Forget(addr net.Addr) {
	if addr == nil {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.conns, addr.String())
}
