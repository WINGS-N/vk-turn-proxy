package wrap

import (
	"log"
	"net"

	dtlsnet "github.com/pion/dtls/v3/pkg/net"
)

// readBufSize bounds how much we read from the underlying conn per packet.
// 65535 covers a max-sized UDP datagram; the actual budget at runtime is
// also constrained by socket-level limits (SO_RCVBUF, TURN ChannelData
// framing, etc.).
const readBufSize = 65535

// PacketConn wraps a net.PacketConn so that every datagram is encrypted on
// send and decrypted on receive using the supplied per-conn Cipher. The
// Cipher carries SRTP-mimicry state (sequence, timestamp, nonce counter)
// and MUST NOT be shared between connections.
//
// Returning the original conn verbatim when cipher is nil keeps call-sites
// symmetric for the "no obfuscation negotiated" path.
func PacketConn(inner net.PacketConn, c Cipher) net.PacketConn {
	if c == nil {
		return inner
	}
	return &wrappedConn{PacketConn: inner, cipher: c}
}

type wrappedConn struct {
	net.PacketConn
	cipher Cipher
}

// ReadFrom decrypts the next datagram. Decryption errors (short packet,
// AEAD authentication failure) cause the packet to be dropped silently
// and the next packet to be read instead, so that unrelated noise on the
// UDP socket cannot stall the read loop.
func (w *wrappedConn) ReadFrom(p []byte) (int, net.Addr, error) {
	buf := make([]byte, readBufSize)
	for {
		n, addr, err := w.PacketConn.ReadFrom(buf)
		if err != nil {
			return 0, addr, err
		}
		plain, openErr := w.cipher.Open(buf[:n])
		if openErr != nil {
			log.Printf("wrap: dropping packet from %s (%d bytes): %s", addr, n, openErr)
			continue
		}
		return copy(p, plain), addr, nil
	}
}

// WriteTo seals the plaintext datagram and writes the result. The returned
// byte count reflects the plaintext length so callers receive a value
// consistent with the unencrypted view they own.
func (w *wrappedConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	sealed, err := w.cipher.Seal(p)
	if err != nil {
		return 0, err
	}
	if _, err := w.PacketConn.WriteTo(sealed, addr); err != nil {
		return 0, err
	}
	return len(p), nil
}

// PacketListener wraps a dtls.PacketListener so each accepted connection
// receives a fresh server-side Cipher minted by the supplied Factory.
//
// Returning the inner listener verbatim when factory is nil keeps
// call-sites symmetric for the "no obfuscation negotiated" path.
func PacketListener(inner dtlsnet.PacketListener, f Factory) dtlsnet.PacketListener {
	if f == nil {
		return inner
	}
	return &wrappedListener{inner: inner, factory: f}
}

type wrappedListener struct {
	inner   dtlsnet.PacketListener
	factory Factory
}

func (l *wrappedListener) Accept() (net.PacketConn, net.Addr, error) {
	pc, addr, err := l.inner.Accept()
	if err != nil {
		return pc, addr, err
	}
	c, cipherErr := l.factory.NewConn(true)
	if cipherErr != nil {
		_ = pc.Close()
		return nil, addr, cipherErr
	}
	return PacketConn(pc, c), addr, nil
}

func (l *wrappedListener) Close() error   { return l.inner.Close() }
func (l *wrappedListener) Addr() net.Addr { return l.inner.Addr() }
