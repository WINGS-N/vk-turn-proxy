package main

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log"

	"github.com/cacggghp/vk-turn-proxy/internal/wrap"
	"github.com/cacggghp/vk-turn-proxy/sessionproto"
)

// resolveWrapConfig validates and normalizes the WRAP CLI options into a
// (cipher, key, mode) triple consumable by turnParams. Returns NONE/nil
// when mode is "off". Generates a random key if mode is enabled and key
// is empty.
func resolveWrapConfig(mode, cipherStr, keyHex string) (sessionproto.WrapCipher, []byte, string, error) {
	if mode == "off" || mode == "" {
		return sessionproto.WrapCipher_WRAP_CIPHER_NONE, nil, "off", nil
	}

	var selected sessionproto.WrapCipher
	switch cipherStr {
	case "srtp-aes-gcm":
		selected = sessionproto.WrapCipher_WRAP_CIPHER_SRTP_AES_256_GCM
	case "srtp-chacha20-poly1305":
		selected = sessionproto.WrapCipher_WRAP_CIPHER_SRTP_CHACHA20_POLY1305
	default:
		return 0, nil, "", fmt.Errorf("unsupported -wrap-cipher %q", cipherStr)
	}

	var key []byte
	if keyHex == "" {
		gen := make([]byte, wrap.KeyLen)
		if _, err := rand.Read(gen); err != nil {
			return 0, nil, "", fmt.Errorf("WRAP key generation: %w", err)
		}
		key = gen
		log.Printf("WRAP: auto-generated key %s (pass -wrap-key=... to pin a fixed one)", hex.EncodeToString(key))
	} else {
		decoded, err := hex.DecodeString(keyHex)
		if err != nil {
			return 0, nil, "", fmt.Errorf("-wrap-key invalid hex: %w", err)
		}
		if len(decoded) != wrap.KeyLen {
			return 0, nil, "", fmt.Errorf("-wrap-key must decode to %d bytes (got %d)", wrap.KeyLen, len(decoded))
		}
		key = decoded
	}
	return selected, key, mode, nil
}
