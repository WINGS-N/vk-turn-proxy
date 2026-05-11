// SPDX-License-Identifier: MIT

package main

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"sync/atomic"

	"golang.org/x/crypto/chacha20"
)

const (
	wrapNonceLen = 12
	wrapKeyLen   = 32
)

// Nonce layout: [4B session prefix | 8B atomic counter, big-endian].
// Session prefix is randomised once at process start; counter monotonically
// increments per-packet. This eliminates the per-packet crypto/rand syscall
// (which on Linux is a getrandom() round-trip ~hundreds of ns) while keeping
// (key, nonce) pairs unique across 2^64 packets per session and 2^32 sessions
// per key. Wire format is byte-identical to the previous random-nonce scheme,
// so server-side decryption is unchanged.
var (
	nonceSessionPrefix [4]byte
	nonceCounter       atomic.Uint64
)

func init() {
	// Best-effort: if rand.Read fails this early, the OS is in trouble and the
	// binary is going to crash anyway during DTLS cert generation. Leaving the
	// prefix zero would still keep nonces unique within this process.
	_, _ = rand.Read(nonceSessionPrefix[:])
}

func fillWrapNonce(dst []byte) {
	_ = dst[wrapNonceLen-1] // bounds-check hint
	copy(dst[:4], nonceSessionPrefix[:])
	binary.BigEndian.PutUint64(dst[4:wrapNonceLen], nonceCounter.Add(1))
}

func genWrapKeyHex() (string, error) {
	key := make([]byte, wrapKeyLen)
	if _, err := rand.Read(key); err != nil {
		return "", fmt.Errorf("wrap: key gen: %w", err)
	}
	return hex.EncodeToString(key), nil
}

func decodeWrapKey(enabled bool, raw string) ([]byte, error) {
	if !enabled {
		return nil, nil
	}
	if raw == "" {
		return nil, errors.New("-wrap requires -wrap-key")
	}
	key, err := hex.DecodeString(raw)
	if err != nil {
		return nil, fmt.Errorf("-wrap-key invalid hex: %w", err)
	}
	if len(key) != wrapKeyLen {
		return nil, fmt.Errorf("-wrap-key must decode to %d bytes (got %d)", wrapKeyLen, len(key))
	}
	return key, nil
}

// wrapInto encrypts payload into dst using the shared scheme
// [12B nonce | ChaCha20-XOR(payload)]. dst must have capacity for
// wrapNonceLen+len(payload). Returns total bytes written. Hot-path callers
// should reuse a single dst buffer to avoid per-packet allocation.
func wrapInto(dst, key, payload []byte) (int, error) {
	if len(key) != wrapKeyLen {
		return 0, fmt.Errorf("wrap: key must be %d bytes (got %d)", wrapKeyLen, len(key))
	}
	total := wrapNonceLen + len(payload)
	if len(dst) < total {
		return 0, errors.New("wrap: dst buffer too small")
	}
	fillWrapNonce(dst[:wrapNonceLen])
	cipher, err := chacha20.NewUnauthenticatedCipher(key, dst[:wrapNonceLen])
	if err != nil {
		return 0, fmt.Errorf("wrap: cipher init: %w", err)
	}
	cipher.XORKeyStream(dst[wrapNonceLen:total], payload)
	return total, nil
}

// wrapPacket allocates a fresh wire buffer. Retained for tests and control
// paths; hot-path code should call wrapInto with a reusable scratch buffer.
func wrapPacket(key, payload []byte) ([]byte, error) {
	out := make([]byte, wrapNonceLen+len(payload))
	n, err := wrapInto(out, key, payload)
	if err != nil {
		return nil, err
	}
	return out[:n], nil
}

func unwrapPacket(key, wire, dst []byte) (int, error) {
	if len(key) != wrapKeyLen {
		return 0, fmt.Errorf("wrap: key must be %d bytes (got %d)", wrapKeyLen, len(key))
	}
	if len(wire) < wrapNonceLen {
		return 0, errors.New("wrap: short packet (no nonce)")
	}
	nonce := wire[:wrapNonceLen]
	ciphertext := wire[wrapNonceLen:]
	if len(ciphertext) > len(dst) {
		return 0, errors.New("wrap: dst buffer too small")
	}
	cipher, err := chacha20.NewUnauthenticatedCipher(key, nonce)
	if err != nil {
		return 0, fmt.Errorf("wrap: cipher init: %w", err)
	}
	cipher.XORKeyStream(dst[:len(ciphertext)], ciphertext)
	return len(ciphertext), nil
}
