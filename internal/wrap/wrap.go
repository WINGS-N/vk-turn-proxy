// Package wrap implements per-packet stream-cipher obfuscation for the TURN
// datapath. It exposes a small Cipher interface with two implementations:
//
//   - AES-256-CTR (default; benefits from ARM AES-NI hardware acceleration).
//   - ChaCha20 (opt-in; software-friendly fallback).
//
// Both write a fresh random 12-byte nonce in front of every packet and apply
// an unauthenticated stream XOR over the payload. The MAC of the DTLS layer
// nested inside provides authentication; the wrap layer only changes what an
// on-path observer sees in the packet bytes.
package wrap

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"

	"golang.org/x/crypto/chacha20"

	"github.com/cacggghp/vk-turn-proxy/sessionproto"
)

// KeyLen is the required key length for every supported cipher (32 bytes).
const KeyLen = 32

// NonceLen is the per-packet nonce length prefixed to every ciphertext.
const NonceLen = 12

// ErrShortCiphertext is returned by Cipher.Open when the input is shorter
// than the nonce prefix.
var ErrShortCiphertext = errors.New("wrap: ciphertext shorter than nonce")

// Cipher seals and opens individual datagrams. Implementations must be safe
// for concurrent use across goroutines.
type Cipher interface {
	// Seal returns nonce||stream_cipher(plaintext). The returned slice is a
	// fresh allocation owned by the caller.
	Seal(plaintext []byte) ([]byte, error)
	// Open decrypts a packet previously produced by a matching Seal. It
	// returns ErrShortCiphertext for inputs shorter than NonceLen.
	Open(ciphertext []byte) ([]byte, error)
	// Overhead returns the per-packet byte overhead added by Seal.
	Overhead() int
}

// New constructs a Cipher from a wire-level cipher selection and key.
//
// Selecting WRAP_CIPHER_NONE or WRAP_CIPHER_UNSPECIFIED returns (nil, nil)
// so the caller can treat "no obfuscation negotiated" uniformly.
func New(selected sessionproto.WrapCipher, key []byte) (Cipher, error) {
	switch selected {
	case sessionproto.WrapCipher_WRAP_CIPHER_UNSPECIFIED,
		sessionproto.WrapCipher_WRAP_CIPHER_NONE:
		return nil, nil
	case sessionproto.WrapCipher_WRAP_CIPHER_AES_256_CTR:
		return newAESCTR(key)
	case sessionproto.WrapCipher_WRAP_CIPHER_CHACHA20_XOR:
		return newChaCha20(key)
	default:
		return nil, fmt.Errorf("wrap: unsupported cipher %v", selected)
	}
}

// GenerateKey returns a fresh random 32-byte key.
func GenerateKey() ([]byte, error) {
	key := make([]byte, KeyLen)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	return key, nil
}

// AES-256-CTR ------------------------------------------------------------

type aesCTRCipher struct {
	block cipher.Block
}

func newAESCTR(key []byte) (Cipher, error) {
	if len(key) != KeyLen {
		return nil, fmt.Errorf("wrap/aes-ctr: key must be %d bytes (got %d)", KeyLen, len(key))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("wrap/aes-ctr: %w", err)
	}
	return &aesCTRCipher{block: block}, nil
}

// derive a 16-byte IV from a 12-byte nonce by appending a fresh 32-bit
// counter (initial value 1, matching AES-GCM convention) — gives every
// packet a unique full IV without reusing keystream blocks across packets
// that share a nonce prefix.
func aesCTRIV(nonce []byte) [aes.BlockSize]byte {
	var iv [aes.BlockSize]byte
	copy(iv[:NonceLen], nonce)
	binary.BigEndian.PutUint32(iv[NonceLen:], 1)
	return iv
}

func (c *aesCTRCipher) Seal(plaintext []byte) ([]byte, error) {
	out := make([]byte, NonceLen+len(plaintext))
	if _, err := rand.Read(out[:NonceLen]); err != nil {
		return nil, err
	}
	iv := aesCTRIV(out[:NonceLen])
	stream := cipher.NewCTR(c.block, iv[:])
	stream.XORKeyStream(out[NonceLen:], plaintext)
	return out, nil
}

func (c *aesCTRCipher) Open(ciphertext []byte) ([]byte, error) {
	if len(ciphertext) < NonceLen {
		return nil, ErrShortCiphertext
	}
	iv := aesCTRIV(ciphertext[:NonceLen])
	plaintext := make([]byte, len(ciphertext)-NonceLen)
	stream := cipher.NewCTR(c.block, iv[:])
	stream.XORKeyStream(plaintext, ciphertext[NonceLen:])
	return plaintext, nil
}

func (c *aesCTRCipher) Overhead() int { return NonceLen }

// ChaCha20 ---------------------------------------------------------------

type chacha20Cipher struct {
	key []byte
}

func newChaCha20(key []byte) (Cipher, error) {
	if len(key) != KeyLen {
		return nil, fmt.Errorf("wrap/chacha20: key must be %d bytes (got %d)", KeyLen, len(key))
	}
	return &chacha20Cipher{key: append([]byte(nil), key...)}, nil
}

func (c *chacha20Cipher) Seal(plaintext []byte) ([]byte, error) {
	out := make([]byte, NonceLen+len(plaintext))
	if _, err := rand.Read(out[:NonceLen]); err != nil {
		return nil, err
	}
	stream, err := chacha20.NewUnauthenticatedCipher(c.key, out[:NonceLen])
	if err != nil {
		return nil, fmt.Errorf("wrap/chacha20: %w", err)
	}
	stream.XORKeyStream(out[NonceLen:], plaintext)
	return out, nil
}

func (c *chacha20Cipher) Open(ciphertext []byte) ([]byte, error) {
	if len(ciphertext) < NonceLen {
		return nil, ErrShortCiphertext
	}
	stream, err := chacha20.NewUnauthenticatedCipher(c.key, ciphertext[:NonceLen])
	if err != nil {
		return nil, fmt.Errorf("wrap/chacha20: %w", err)
	}
	plaintext := make([]byte, len(ciphertext)-NonceLen)
	stream.XORKeyStream(plaintext, ciphertext[NonceLen:])
	return plaintext, nil
}

func (c *chacha20Cipher) Overhead() int { return NonceLen }
