package wbstream

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
)

// E2EKeySize is the expected size of the E2E key (AES-256).
const E2EKeySize = 32

// E2E is an optional AES-256-GCM wrapper applied on top of LiveKit DataPacket
// payloads. The same key must be configured on both peers (typically shipped
// through the wingsv:// import link as a base64 secret).
type E2E struct {
	aead cipher.AEAD
}

// NewE2E returns an E2E wrapper. key must be 32 bytes (AES-256 key size).
// Pass nil/empty key to obtain a no-op wrapper.
func NewE2E(key []byte) (*E2E, error) {
	if len(key) == 0 {
		return nil, nil
	}
	if len(key) != E2EKeySize {
		return nil, fmt.Errorf("e2e key must be %d bytes, got %d", E2EKeySize, len(key))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("aes: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("aes-gcm: %w", err)
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
		return nil, fmt.Errorf("aes-gcm open: %w", err)
	}
	return plaintext, nil
}

// Active reports whether E2E actually wraps payloads.
func (e *E2E) Active() bool {
	return e != nil && e.aead != nil
}
