package main

import (
	"encoding/hex"
	"fmt"
	"log"
	"net"

	"github.com/cacggghp/vk-turn-proxy/internal/wrap"
	"github.com/cacggghp/vk-turn-proxy/sessionproto"
)

// wrapPolicy is the server-side WRAP negotiation policy resolved from
// CLI flags. enabled=false short-circuits all WRAP handling. When
// enabled:
//   - allowedCiphers lists the AEAD suites we are willing to accept,
//     in our preference order;
//   - presetKey, if non-empty, is the fixed shared key — it ALWAYS
//     takes precedence over any wrap_key_proposal the client sends;
//   - acceptClientKeys lets us refuse client-proposed keys when no
//     preset is configured (then WRAP only works if presetKey is set).
type wrapPolicy struct {
	enabled          bool
	allowedCiphers   []sessionproto.WrapCipher
	presetKey        []byte
	acceptClientKeys bool
}

func resolveServerWrapPolicy(mode, allowedCipher, keyHex string, acceptClientKeys bool) (*wrapPolicy, error) {
	switch mode {
	case "", "off":
		return &wrapPolicy{enabled: false}, nil
	case "on":
	default:
		return nil, fmt.Errorf("unsupported -wrap-mode %q (off|on)", mode)
	}

	var allowed []sessionproto.WrapCipher
	switch allowedCipher {
	case "", "any":
		allowed = []sessionproto.WrapCipher{
			sessionproto.WrapCipher_WRAP_CIPHER_SRTP_AES_256_GCM,
			sessionproto.WrapCipher_WRAP_CIPHER_SRTP_CHACHA20_POLY1305,
		}
	case "srtp-aes-gcm":
		allowed = []sessionproto.WrapCipher{sessionproto.WrapCipher_WRAP_CIPHER_SRTP_AES_256_GCM}
	case "srtp-chacha20-poly1305":
		allowed = []sessionproto.WrapCipher{sessionproto.WrapCipher_WRAP_CIPHER_SRTP_CHACHA20_POLY1305}
	default:
		return nil, fmt.Errorf("unsupported -wrap-cipher %q (any|srtp-aes-gcm|srtp-chacha20-poly1305)", allowedCipher)
	}

	policy := &wrapPolicy{
		enabled:          true,
		allowedCiphers:   allowed,
		acceptClientKeys: acceptClientKeys,
	}
	if keyHex != "" {
		decoded, err := hex.DecodeString(keyHex)
		if err != nil {
			return nil, fmt.Errorf("-wrap-key invalid hex: %w", err)
		}
		if len(decoded) != wrap.KeyLen {
			return nil, fmt.Errorf("-wrap-key must decode to %d bytes (got %d)", wrap.KeyLen, len(decoded))
		}
		policy.presetKey = decoded
	}
	if !policy.acceptClientKeys && policy.presetKey == nil {
		return nil, fmt.Errorf("-wrap-mode=on with -wrap-accept-client-keys=false requires -wrap-key")
	}
	return policy, nil
}

// pickServerWrapCipher intersects the server's accepted suites with the
// client's offered list, honoring the client's preference order: the
// first cipher from clientOffered that the server also allows wins.
// Returns WRAP_CIPHER_NONE on no overlap.
//
// This matches the TLS-style convention where the client expresses
// intent ("I prefer ChaCha but will accept AES") and the server only
// vetoes when something is forbidden. Without this, an explicit user
// pick on the client (e.g. ChaCha) silently downgrades to whatever the
// server has at the top of its own allowlist (typically AES under
// -wrap-cipher=any).
func pickServerWrapCipher(
	allowed []sessionproto.WrapCipher,
	clientOffered []sessionproto.WrapCipher,
) sessionproto.WrapCipher {
	if len(allowed) == 0 || len(clientOffered) == 0 {
		return sessionproto.WrapCipher_WRAP_CIPHER_NONE
	}
	allowedSet := make(map[sessionproto.WrapCipher]struct{}, len(allowed))
	for _, c := range allowed {
		allowedSet[c] = struct{}{}
	}
	for _, c := range clientOffered {
		if _, ok := allowedSet[c]; ok {
			return c
		}
	}
	return sessionproto.WrapCipher_WRAP_CIPHER_NONE
}

// chooseKey applies the policy: preset key wins; otherwise the
// client-proposed key is accepted if acceptClientKeys is true. Returns
// the chosen key and a label for logging, or (nil, "") when no usable
// key is available.
func (p *wrapPolicy) chooseKey(clientProposal []byte) ([]byte, string) {
	if p == nil || !p.enabled {
		return nil, ""
	}
	if len(p.presetKey) == wrap.KeyLen {
		return p.presetKey, "preset"
	}
	if p.acceptClientKeys && len(clientProposal) == wrap.KeyLen {
		// defensive copy so subsequent buffer reuse can't mutate it
		key := append([]byte(nil), clientProposal...)
		return key, "client"
	}
	return nil, ""
}

// negotiateWrapForSession runs the WRAP negotiation for one mu/v1
// SessionHello on the server side. Returns the cipher to echo in
// ServerHello.selected_wrap_cipher and (if non-NONE) a ready-to-use
// Cipher instance that the caller should Enable on the per-conn
// StatefulConn after the ServerHello has been written raw.
func negotiateWrapForSession(
	remote net.Addr,
	hello *sessionproto.ClientHello,
	policy *wrapPolicy,
) (sessionproto.WrapCipher, wrap.Cipher) {
	if policy == nil || !policy.enabled || hello == nil {
		return sessionproto.WrapCipher_WRAP_CIPHER_NONE, nil
	}
	selected := pickServerWrapCipher(policy.allowedCiphers, hello.GetSupportedWrapCiphers())
	if selected == sessionproto.WrapCipher_WRAP_CIPHER_NONE {
		return sessionproto.WrapCipher_WRAP_CIPHER_NONE, nil
	}
	key, source := policy.chooseKey(hello.GetWrapKeyProposal())
	if key == nil {
		log.Printf("WRAP negotiation: cipher %s offered by %s but no usable key (client_proposal=%d, preset=%t); declining",
			selected, remote, len(hello.GetWrapKeyProposal()), policy.presetKey != nil)
		return sessionproto.WrapCipher_WRAP_CIPHER_NONE, nil
	}
	c, err := wrap.New(selected, key, true)
	if err != nil {
		log.Printf("WRAP cipher init failed for %s: %v; declining", remote, err)
		return sessionproto.WrapCipher_WRAP_CIPHER_NONE, nil
	}
	log.Printf("WRAP negotiated for %s: cipher=%s key_source=%s", remote, selected, source)
	return selected, c
}
