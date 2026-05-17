package wrap

import (
	"log"
	"net"
)

// readBufSize bounds how much we read from the underlying conn per packet.
// 65535 covers a max-sized UDP datagram; the actual budget at runtime is
// also constrained by socket-level limits (SO_RCVBUF, TURN ChannelData
// framing, etc.).
const readBufSize = 65535

// PacketConn wraps a net.PacketConn so that every datagram is encrypted on
// send and decrypted on receive using the supplied Cipher.
//
// Returning nil cipher passes through to the original conn unchanged, which
// keeps call-sites symmetric for "no obfuscation negotiated" paths.
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

// ReadFrom decrypts the next datagram. Decryption errors (currently only the
// "shorter than nonce" case) cause the packet to be dropped silently and the
// next packet to be read instead, so that unrelated noise on the UDP socket
// cannot stall the read loop.
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
