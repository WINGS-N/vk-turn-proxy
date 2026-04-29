package wbstream

import (
	"crypto/rand"
	"errors"
	"fmt"

	"golang.org/x/crypto/chacha20poly1305"
)

// E2E is an optional chacha20-poly1305 wrapper applied on top of LiveKit
// DataPacket payloads. The same key must be configured on both peers (typically
// shipped through the wingsv:// import link as a base64 secret).
type E2E struct {
	aead interface {
		NonceSize() int
		Overhead() int
		Seal(dst, nonce, plaintext, additionalData []byte) []byte
		Open(dst, nonce, ciphertext, additionalData []byte) ([]byte, error)
	}
}

// NewE2E returns an E2E wrapper. key must be 32 bytes (chacha20-poly1305 key size).
// Pass nil/empty key to obtain a no-op wrapper.
func NewE2E(key []byte) (*E2E, error) {
	if len(key) == 0 {
		return nil, nil
	}
	if len(key) != chacha20poly1305.KeySize {
		return nil, fmt.Errorf("e2e key must be %d bytes, got %d", chacha20poly1305.KeySize, len(key))
	}
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, fmt.Errorf("chacha20poly1305: %w", err)
	}
	return &E2E{aead: aead}, nil
}

// Seal returns a fresh ciphertext: nonce || encrypted_payload.
func (e *E2E) Seal(plaintext []byte) ([]byte, error) {
	if e == nil || e.aead == nil {
		return plaintext, nil
	}
	nonce := make([]byte, e.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("rand nonce: %w", err)
	}
	out := make([]byte, 0, len(nonce)+len(plaintext)+e.aead.Overhead())
	out = append(out, nonce...)
	out = e.aead.Seal(out, nonce, plaintext, nil)
	return out, nil
}

// Open verifies and decrypts a ciphertext produced by Seal. Format: nonce || encrypted.
func (e *E2E) Open(ciphertext []byte) ([]byte, error) {
	if e == nil || e.aead == nil {
		return ciphertext, nil
	}
	if len(ciphertext) < e.aead.NonceSize()+e.aead.Overhead() {
		return nil, errors.New("ciphertext too short")
	}
	nonce := ciphertext[:e.aead.NonceSize()]
	body := ciphertext[e.aead.NonceSize():]
	plaintext, err := e.aead.Open(nil, nonce, body, nil)
	if err != nil {
		return nil, fmt.Errorf("chacha20poly1305 open: %w", err)
	}
	return plaintext, nil
}

// Active reports whether E2E actually wraps payloads.
func (e *E2E) Active() bool {
	return e != nil && e.aead != nil
}
