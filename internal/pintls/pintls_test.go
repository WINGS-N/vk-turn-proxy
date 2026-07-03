package pintls

import (
	"encoding/base64"
	"testing"
)

func TestParsePinRoundTrip(t *testing.T) {
	var raw [PinLen]byte
	for i := range raw {
		raw[i] = byte(i)
	}
	b64 := base64.StdEncoding.EncodeToString(raw[:])
	for _, in := range []string{b64, "sha256/" + b64, "  sha256/" + b64 + "  "} {
		got, err := ParsePin(in)
		if err != nil {
			t.Fatalf("ParsePin(%q): %v", in, err)
		}
		if got != raw {
			t.Fatalf("ParsePin(%q) = %x, want %x", in, got, raw)
		}
	}
}

func TestParsePinRejectsBad(t *testing.T) {
	if _, err := ParsePin(base64.StdEncoding.EncodeToString([]byte("short"))); err == nil {
		t.Fatal("expected an error for a 5-byte pin")
	}
	if _, err := ParsePin("!!!not-base64"); err == nil {
		t.Fatal("expected an error for invalid base64")
	}
}
