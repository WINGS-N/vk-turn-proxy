// Package wrap implements per-packet SRTP-mimicry obfuscation for the TURN
// datapath. The wire format mimics SRTP (RFC 3550 / RFC 7714 AEAD profile)
// so that VK TURN, which appears to forward only SRTP/DTLS-shaped
// ChannelData payloads on the fast path, accepts the obfuscated traffic.
//
// Wire format per datagram (40-byte overhead):
//
//	[12B RTP header | 12B explicit nonce | AEAD ciphertext | 16B tag]
//
// RTP header (RFC 3550):
//
//	byte 0:    0x80         V=2, P=0, X=0, CC=0
//	byte 1:    0x6F         M=0, PT=111 (opus, typical voice PT)
//	bytes 2-3: seq16 BE     monotonic, init random
//	bytes 4-7: ts32 BE      monotonic, init random, increments by 960
//	                        (one Opus frame = 20ms @ 48kHz)
//	bytes 8-11: SSRC        random per conn, MSB encodes direction
//
// Explicit nonce (12B) = 4B sessionID || 8B counter (big-endian). sessionID
// MSB matches SSRC MSB (direction bit: client clears, server sets) so that
// nonces never collide across the two directions under the same key.
// counter starts at a random uint64 to avoid reuse across process restarts.
// AAD = first 24 bytes (RTP header || nonce) — any tampering with the RTP
// header breaks Open.
//
// Each connection (each accepted listener stream and each client worker)
// holds its own Cipher with fresh per-conn state. Use NewFactory to
// construct a Factory that mints those per-conn ciphers.
//
// Original SRTP-mimicry wire format and AEAD construction adapted from
// samosvalishe/vk-turn-proxy commit cd14d25.
package wrap

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"sync/atomic"

	"golang.org/x/crypto/chacha20poly1305"

	"github.com/cacggghp/vk-turn-proxy/sessionproto"
)

// KeyLen is the required key length for every supported cipher (32 bytes).
const KeyLen = 32

// MaxOverhead returns the largest per-packet byte overhead any of our
// SRTP-mimicry ciphers can add (RTP header + nonce + AEAD tag = 40 B).
// Useful for sizing receive buffers without holding a Cipher reference.
func MaxOverhead() int { return overhead }

// Per-packet wire-format constants.
const (
	rtpHdrLen  = 12
	nonceLen   = 12
	tagLen     = 16
	headerLen  = rtpHdrLen + nonceLen // 24 (AAD scope)
	overhead   = headerLen + tagLen   // 40
	rtpVersion = 0x80                 // V=2, P=0, X=0, CC=0
	rtpPT      = 0x6F                 // M=0, PT=111 (opus)
	tsStep     = 960                  // 20ms @ 48kHz
)

// ErrShortCiphertext is returned by Cipher.Open when the wire packet is
// shorter than the fixed-size header + tag.
var ErrShortCiphertext = errors.New("wrap: ciphertext shorter than overhead")

// Cipher seals and opens individual datagrams. Each Cipher carries its own
// RTP sequence/timestamp/SSRC and nonce counter; instances MUST NOT be
// shared between connections.
type Cipher interface {
	Seal(plaintext []byte) ([]byte, error)
	Open(ciphertext []byte) ([]byte, error)
	Overhead() int
}

// Factory mints fresh per-connection Cipher instances under a fixed key.
// The isServer flag drives the direction bit (MSB of sessionID/SSRC).
type Factory interface {
	NewConn(isServer bool) (Cipher, error)
}

// NewFactory constructs a Factory for the given wire-level cipher
// selection and key. Selecting WRAP_CIPHER_NONE / _UNSPECIFIED returns
// (nil, nil) so callers can treat "no obfuscation negotiated" uniformly.
func NewFactory(selected sessionproto.WrapCipher, key []byte) (Factory, error) {
	switch selected {
	case sessionproto.WrapCipher_WRAP_CIPHER_UNSPECIFIED,
		sessionproto.WrapCipher_WRAP_CIPHER_NONE:
		return nil, nil
	case sessionproto.WrapCipher_WRAP_CIPHER_SRTP_AES_256_GCM:
		return newAESGCMFactory(key)
	case sessionproto.WrapCipher_WRAP_CIPHER_SRTP_CHACHA20_POLY1305:
		return newChaChaFactory(key)
	default:
		return nil, fmt.Errorf("wrap: unsupported cipher %v", selected)
	}
}

// New is a convenience that creates a Factory and immediately mints one
// connection Cipher under it. Server-side listeners should call
// NewFactory and then NewConn per accept instead, so that each peer gets
// independent RTP state and nonce counter.
func New(selected sessionproto.WrapCipher, key []byte, isServer bool) (Cipher, error) {
	f, err := NewFactory(selected, key)
	if err != nil || f == nil {
		return nil, err
	}
	return f.NewConn(isServer)
}

// GenerateKey returns a fresh random 32-byte key.
func GenerateKey() ([]byte, error) {
	key := make([]byte, KeyLen)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	return key, nil
}

// --- AES-256-GCM factory + cipher (ARM AES-NI fast path) -----------------

type aesGCMFactory struct{ aead cipher.AEAD }

func newAESGCMFactory(key []byte) (Factory, error) {
	if len(key) != KeyLen {
		return nil, fmt.Errorf("wrap/aes-gcm: key must be %d bytes (got %d)", KeyLen, len(key))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("wrap/aes-gcm: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("wrap/aes-gcm: %w", err)
	}
	return &aesGCMFactory{aead: aead}, nil
}

func (f *aesGCMFactory) NewConn(isServer bool) (Cipher, error) {
	return newSRTPConn(f.aead, isServer)
}

// --- ChaCha20-Poly1305 factory + cipher ---------------------------------

type chachaFactory struct{ aead cipher.AEAD }

func newChaChaFactory(key []byte) (Factory, error) {
	if len(key) != KeyLen {
		return nil, fmt.Errorf("wrap/chacha20-poly1305: key must be %d bytes (got %d)", KeyLen, len(key))
	}
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, fmt.Errorf("wrap/chacha20-poly1305: %w", err)
	}
	return &chachaFactory{aead: aead}, nil
}

func (f *chachaFactory) NewConn(isServer bool) (Cipher, error) {
	return newSRTPConn(f.aead, isServer)
}

// --- SRTP-mimicry per-conn cipher (AEAD-agnostic) -----------------------

type srtpConn struct {
	aead      cipher.AEAD
	sessionID [4]byte // nonce prefix; MSB encodes direction
	ssrc      [4]byte // RTP SSRC; MSB encodes direction
	counter   atomic.Uint64
	seq       atomic.Uint32 // used as uint16 (RTP sequence)
	timestamp atomic.Uint32 // RTP timestamp
}

func newSRTPConn(aead cipher.AEAD, isServer bool) (Cipher, error) {
	c := &srtpConn{aead: aead}

	var rnd [16]byte
	if _, err := rand.Read(rnd[:]); err != nil {
		return nil, fmt.Errorf("wrap: rand init: %w", err)
	}
	copy(c.sessionID[:], rnd[0:4])
	copy(c.ssrc[:], rnd[4:8])
	if isServer {
		c.sessionID[0] |= 0x80
		c.ssrc[0] |= 0x80
	} else {
		c.sessionID[0] &^= 0x80
		c.ssrc[0] &^= 0x80
	}
	c.seq.Store(uint32(binary.BigEndian.Uint16(rnd[8:10])))
	c.timestamp.Store(binary.BigEndian.Uint32(rnd[10:14]))

	var cb [8]byte
	if _, err := rand.Read(cb[:]); err != nil {
		return nil, fmt.Errorf("wrap: counter rand: %w", err)
	}
	c.counter.Store(binary.BigEndian.Uint64(cb[:]))
	return c, nil
}

func (c *srtpConn) Overhead() int { return overhead }

func (c *srtpConn) Seal(plaintext []byte) ([]byte, error) {
	out := make([]byte, overhead+len(plaintext))

	// RTP header.
	out[0] = rtpVersion
	out[1] = rtpPT
	seq := uint16(c.seq.Add(1) - 1)
	binary.BigEndian.PutUint16(out[2:4], seq)
	ts := c.timestamp.Add(tsStep) - tsStep
	binary.BigEndian.PutUint32(out[4:8], ts)
	copy(out[8:12], c.ssrc[:])

	// Explicit nonce: 4B sessionID || 8B counter.
	copy(out[rtpHdrLen:rtpHdrLen+4], c.sessionID[:])
	ctr := c.counter.Add(1) - 1
	binary.BigEndian.PutUint64(out[rtpHdrLen+4:rtpHdrLen+nonceLen], ctr)

	nonce := out[rtpHdrLen : rtpHdrLen+nonceLen]
	aad := out[:headerLen]
	ctPos := headerLen
	copy(out[ctPos:], plaintext)
	c.aead.Seal(out[ctPos:ctPos], nonce, out[ctPos:ctPos+len(plaintext)], aad)

	return out, nil
}

func (c *srtpConn) Open(wire []byte) ([]byte, error) {
	if len(wire) < overhead {
		return nil, ErrShortCiphertext
	}
	nonce := wire[rtpHdrLen : rtpHdrLen+nonceLen]
	aad := wire[:headerLen]
	ct := wire[headerLen:]
	plain := make([]byte, 0, len(ct)-tagLen)
	plain, err := c.aead.Open(plain, nonce, ct, aad)
	if err != nil {
		return nil, fmt.Errorf("wrap: AEAD open: %w", err)
	}
	return plain, nil
}
