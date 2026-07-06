// Package tokenaead is a gRPC transport that encrypts the connection with
// AES-256-GCM using a key derived from a shared bearer token, instead of X.509
// certificates. Because both peers derive the same keys from the token there is
// NO handshake on the wire - the first bytes are already the (encrypted) HTTP/2
// preface - so it sidesteps the TLS cert-chain that overflows a k8s pod's reduced
// MTU. Possession of the token is both authentication and the encryption key: a
// wrong token cannot decrypt the stream, so the connection simply fails.
//
// The token keys two independent directions (client->server, server->client),
// each an AES-256-GCM AEAD with its own monotonically increasing record counter
// as the nonce, so nonces never repeat under a key. There is no forward secrecy
// (a leaked token decrypts captured traffic); acceptable for a management channel
// already gated by that same token.
package tokenaead

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/binary"
	"io"
	"net"
	"sync"

	"google.golang.org/grpc/credentials"
)

const (
	keyLen        = 32        // AES-256
	nonceLen      = 12        // GCM standard nonce
	maxPlainChunk = 16 * 1024 // per-record plaintext cap
	protocolName  = "wingsv-token-aes256gcm"
	hkdfSalt      = "wingsv-mgmt-grpc-v1"
)

func deriveKey(token []byte, label string) []byte {
	// A non-empty token is required upstream; hkdf.Key never fails for these
	// fixed lengths, so a derivation error is treated as a programming bug.
	key, err := hkdf.Key(sha256.New, token, []byte(hkdfSalt), label, keyLen)
	if err != nil {
		panic("tokenaead: hkdf: " + err.Error())
	}
	return key
}

func newGCM(key []byte) cipher.AEAD {
	block, err := aes.NewCipher(key)
	if err != nil {
		panic("tokenaead: aes: " + err.Error())
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		panic("tokenaead: gcm: " + err.Error())
	}
	return aead
}

// aeadConn wraps a net.Conn, encrypting each write into a length-prefixed
// AES-256-GCM record and decrypting on read. Reads and writes use independent
// AEADs and counters so the two directions never share a nonce space.
type aeadConn struct {
	net.Conn
	writeAEAD, readAEAD cipher.AEAD
	writeCtr, readCtr   uint64
	writeMu, readMu     sync.Mutex
	readBuf             []byte
}

func nonce(counter uint64) []byte {
	n := make([]byte, nonceLen)
	binary.BigEndian.PutUint64(n[nonceLen-8:], counter)
	return n
}

func (a *aeadConn) Write(p []byte) (int, error) {
	a.writeMu.Lock()
	defer a.writeMu.Unlock()
	written := 0
	for len(p) > 0 {
		chunk := p
		if len(chunk) > maxPlainChunk {
			chunk = chunk[:maxPlainChunk]
		}
		ct := a.writeAEAD.Seal(nil, nonce(a.writeCtr), chunk, nil)
		a.writeCtr++
		var hdr [4]byte
		binary.BigEndian.PutUint32(hdr[:], uint32(len(ct)))
		if _, err := a.Conn.Write(hdr[:]); err != nil {
			return written, err
		}
		if _, err := a.Conn.Write(ct); err != nil {
			return written, err
		}
		written += len(chunk)
		p = p[len(chunk):]
	}
	return written, nil
}

func (a *aeadConn) Read(p []byte) (int, error) {
	a.readMu.Lock()
	defer a.readMu.Unlock()
	if len(a.readBuf) == 0 {
		var hdr [4]byte
		if _, err := io.ReadFull(a.Conn, hdr[:]); err != nil {
			return 0, err
		}
		ct := make([]byte, binary.BigEndian.Uint32(hdr[:]))
		if _, err := io.ReadFull(a.Conn, ct); err != nil {
			return 0, err
		}
		pt, err := a.readAEAD.Open(nil, nonce(a.readCtr), ct, nil)
		if err != nil {
			return 0, err
		}
		a.readCtr++
		a.readBuf = pt
	}
	n := copy(p, a.readBuf)
	a.readBuf = a.readBuf[n:]
	return n, nil
}

type authInfo struct {
	credentials.CommonAuthInfo
}

func (authInfo) AuthType() string { return protocolName }

// Creds is a gRPC TransportCredentials that secures the connection with the
// token-derived AES-256-GCM stream. Use Client on a dialer and Server on a
// listener; both must be built from the same token.
type Creds struct {
	c2s, s2c []byte
	server   bool
}

// Client builds dialer credentials keyed by token.
func Client(token string) *Creds {
	return &Creds{c2s: deriveKey([]byte(token), "c2s"), s2c: deriveKey([]byte(token), "s2c")}
}

// Server builds listener credentials keyed by token.
func Server(token string) *Creds {
	return &Creds{c2s: deriveKey([]byte(token), "c2s"), s2c: deriveKey([]byte(token), "s2c"), server: true}
}

func wrap(raw net.Conn, writeKey, readKey []byte) (net.Conn, credentials.AuthInfo, error) {
	return &aeadConn{Conn: raw, writeAEAD: newGCM(writeKey), readAEAD: newGCM(readKey)},
		authInfo{CommonAuthInfo: credentials.CommonAuthInfo{SecurityLevel: credentials.PrivacyAndIntegrity}}, nil
}

// ClientHandshake wraps raw for the dialing side: it writes c2s, reads s2c.
func (c *Creds) ClientHandshake(_ context.Context, _ string, raw net.Conn) (net.Conn, credentials.AuthInfo, error) {
	return wrap(raw, c.c2s, c.s2c)
}

// ServerHandshake wraps raw for the listening side: it writes s2c, reads c2s.
func (c *Creds) ServerHandshake(raw net.Conn) (net.Conn, credentials.AuthInfo, error) {
	return wrap(raw, c.s2c, c.c2s)
}

func (c *Creds) Info() credentials.ProtocolInfo {
	return credentials.ProtocolInfo{SecurityProtocol: protocolName}
}

func (c *Creds) Clone() credentials.TransportCredentials { cc := *c; return &cc }

func (c *Creds) OverrideServerName(string) error { return nil }
