package main

import (
	"encoding/hex"
	"fmt"

	"github.com/cacggghp/vk-turn-proxy/internal/wrap"
	"github.com/cacggghp/vk-turn-proxy/sessionproto"
)

// resolveServerWrapConfig validates the server-side WRAP CLI options and
// builds the Factory to apply to the UDP listener. Returns (nil, nil) when
// WRAP is disabled, so the caller can keep raw dtls.Listen for backward
// compatibility with older clients.
func resolveServerWrapConfig(mode, cipherStr, keyHex string) (wrap.Factory, error) {
	if mode != "on" {
		return nil, nil
	}
	if keyHex == "" {
		return nil, fmt.Errorf("-wrap-mode=on requires -wrap-key")
	}
	key, err := hex.DecodeString(keyHex)
	if err != nil {
		return nil, fmt.Errorf("-wrap-key invalid hex: %w", err)
	}
	if len(key) != wrap.KeyLen {
		return nil, fmt.Errorf("-wrap-key must decode to %d bytes (got %d)", wrap.KeyLen, len(key))
	}
	var selected sessionproto.WrapCipher
	switch cipherStr {
	case "srtp-aes-gcm":
		selected = sessionproto.WrapCipher_WRAP_CIPHER_SRTP_AES_256_GCM
	case "srtp-chacha20-poly1305":
		selected = sessionproto.WrapCipher_WRAP_CIPHER_SRTP_CHACHA20_POLY1305
	default:
		return nil, fmt.Errorf("unsupported -wrap-cipher %q", cipherStr)
	}
	return wrap.NewFactory(selected, key)
}
