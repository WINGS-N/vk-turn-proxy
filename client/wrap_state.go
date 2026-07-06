package main

import (
	"fmt"
	"log"

	"github.com/cacggghp/vk-turn-proxy/internal/wrap"
	"github.com/cacggghp/vk-turn-proxy/sessionproto"
)

// clientSupportedWrapCiphers returns the list of WRAP ciphers this
// client is willing to use, in preference order. The first entry is the
// one explicitly configured via -wrap-cipher; we additionally advertise
// the other cipher as a fallback so the server can downgrade if its
// allowlist intersects only the secondary suite.
//
// Returns nil when WRAP is fully disabled (wrapCipher == NONE /
// UNSPECIFIED) so the SessionHello carries no negotiation fields.
func clientSupportedWrapCiphers(cipher sessionproto.WrapCipher) []sessionproto.WrapCipher {
	switch cipher {
	case sessionproto.WrapCipher_WRAP_CIPHER_SRTP_AES_256_GCM:
		return []sessionproto.WrapCipher{
			sessionproto.WrapCipher_WRAP_CIPHER_SRTP_AES_256_GCM,
			sessionproto.WrapCipher_WRAP_CIPHER_SRTP_CHACHA20_POLY1305,
		}
	case sessionproto.WrapCipher_WRAP_CIPHER_SRTP_CHACHA20_POLY1305:
		return []sessionproto.WrapCipher{
			sessionproto.WrapCipher_WRAP_CIPHER_SRTP_CHACHA20_POLY1305,
			sessionproto.WrapCipher_WRAP_CIPHER_SRTP_AES_256_GCM,
		}
	default:
		return nil
	}
}

// applyServerWrapChoice consumes ServerHello.selected_wrap_cipher and
// installs the matching Cipher on the worker's StatefulConn (registered
// in turnParams.wrapStates under streamID). Honors wrapMode semantics:
//
//   - mode "required": NONE/UNSPECIFIED from the server is a hard error.
//   - mode "preferred": NONE/UNSPECIFIED stays raw (no wrap). Connection
//     still works through VK TURN's slow lane.
//   - mode "off": nothing to do regardless of server's answer.
//
// When a non-NONE cipher arrives, we Enable wrap on this worker's
// per-conn StatefulConn so subsequent DTLS ApplicationData records go
// SRTP-shaped from the next outbound write.
func applyServerWrapChoice(p *turnParams, snap *liveSnapshot, streamID int, hello *sessionproto.ServerHello) error {
	if p == nil || snap == nil {
		return nil
	}
	selected := hello.GetSelectedWrapCipher()
	if snap.wrapMode == "" || snap.wrapMode == "off" {
		if selected != sessionproto.WrapCipher_WRAP_CIPHER_UNSPECIFIED &&
			selected != sessionproto.WrapCipher_WRAP_CIPHER_NONE {
			log.Printf("[STREAM %d] server selected WRAP cipher=%s but local mode is off; ignoring", streamID, selected)
		}
		return nil
	}

	if selected == sessionproto.WrapCipher_WRAP_CIPHER_UNSPECIFIED ||
		selected == sessionproto.WrapCipher_WRAP_CIPHER_NONE {
		if snap.wrapMode == "required" {
			return fmt.Errorf("server declined WRAP (selected=%s) but local mode is required", selected)
		}
		log.Printf("[STREAM %d] server declined WRAP (selected=%s); staying raw", streamID, selected)
		return nil
	}

	cipher, err := wrap.New(selected, snap.wrapKey, false)
	if err != nil {
		return fmt.Errorf("WRAP cipher init for selected=%s: %w", selected, err)
	}
	if cipher == nil {
		return fmt.Errorf("unexpected nil cipher for selected=%s", selected)
	}

	if p.wrapStates == nil {
		return fmt.Errorf("wrap state registry missing")
	}
	v, ok := p.wrapStates.Load(streamID)
	if !ok {
		return fmt.Errorf("no StatefulConn registered for stream %d", streamID)
	}
	sc, ok := v.(*wrap.StatefulConn)
	if !ok {
		return fmt.Errorf("stream %d wrap state is not *StatefulConn", streamID)
	}
	sc.Enable(cipher)
	log.Printf("[STREAM %d] WRAP enabled in-band: cipher=%s", streamID, selected)
	return nil
}
