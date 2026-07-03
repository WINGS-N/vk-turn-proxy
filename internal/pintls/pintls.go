// Package pintls builds a TLS client config that trusts a control-plane peer
// (the wingsv-panel, or a sibling node) by its CA SPKI pin rather than by a
// publicly trusted certificate chain. It mirrors the panel's pki.PinnedClient
// verification so the DTLS PROVISION path can reach a no-domain panel securely.
package pintls

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"strings"
)

// PinLen is the length of an SPKI pin (SHA-256 digest).
const PinLen = sha256.Size

// ClientConfig returns a tls.Config that skips the default chain/hostname checks
// and instead requires that some certificate the server presents has a
// SubjectPublicKeyInfo hash matching one of pins.
func ClientConfig(pins ...[PinLen]byte) *tls.Config {
	return &tls.Config{
		InsecureSkipVerify: true,
		VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			for _, raw := range rawCerts {
				cert, err := x509.ParseCertificate(raw)
				if err != nil {
					continue
				}
				got := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
				for _, pin := range pins {
					if got == pin {
						return nil
					}
				}
			}
			return errors.New("pintls: no presented certificate matches a pinned CA")
		},
	}
}

// ParsePin decodes a pin in either raw base64 or the "sha256/<base64>" form.
func ParsePin(s string) ([PinLen]byte, error) {
	s = strings.TrimPrefix(strings.TrimSpace(s), "sha256/")
	raw, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return [PinLen]byte{}, err
	}
	if len(raw) != PinLen {
		return [PinLen]byte{}, errors.New("pintls: pin must decode to 32 bytes")
	}
	var pin [PinLen]byte
	copy(pin[:], raw)
	return pin, nil
}
