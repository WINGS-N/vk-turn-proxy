package wrap

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"testing"

	"github.com/cacggghp/vk-turn-proxy/sessionproto"
)

func mustKey(t *testing.T) []byte {
	t.Helper()
	k, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	if len(k) != KeyLen {
		t.Fatalf("GenerateKey returned %d bytes, want %d", len(k), KeyLen)
	}
	return k
}

func newPair(t *testing.T, selected sessionproto.WrapCipher) (Cipher, Cipher) {
	t.Helper()
	key := mustKey(t)
	f, err := NewFactory(selected, key)
	if err != nil {
		t.Fatalf("NewFactory(%v): %v", selected, err)
	}
	if f == nil {
		t.Fatalf("NewFactory(%v): unexpected nil factory", selected)
	}
	client, err := f.NewConn(false)
	if err != nil {
		t.Fatalf("NewConn(client): %v", err)
	}
	server, err := f.NewConn(true)
	if err != nil {
		t.Fatalf("NewConn(server): %v", err)
	}
	return client, server
}

func roundTrip(t *testing.T, selected sessionproto.WrapCipher) {
	t.Helper()
	client, server := newPair(t, selected)

	for _, n := range []int{0, 1, 16, 1500, 16000} {
		plaintext := make([]byte, n)
		if _, err := rand.Read(plaintext); err != nil {
			t.Fatalf("rand: %v", err)
		}
		wire, err := client.Seal(plaintext)
		if err != nil {
			t.Fatalf("Seal n=%d: %v", n, err)
		}
		if len(wire) != n+client.Overhead() {
			t.Fatalf("Seal length mismatch n=%d: got %d want %d", n, len(wire), n+client.Overhead())
		}
		if wire[0] != rtpVersion {
			t.Fatalf("RTP byte0 = 0x%02X, want 0x%02X", wire[0], rtpVersion)
		}
		if wire[1] != rtpPT {
			t.Fatalf("RTP byte1 (PT) = 0x%02X, want 0x%02X", wire[1], rtpPT)
		}
		opened, err := server.Open(wire)
		if err != nil {
			t.Fatalf("Open n=%d: %v", n, err)
		}
		if !bytes.Equal(plaintext, opened) {
			t.Fatalf("round-trip mismatch n=%d", n)
		}
	}
}

func TestRoundTripAESGCM(t *testing.T) {
	roundTrip(t, sessionproto.WrapCipher_WRAP_CIPHER_SRTP_AES_256_GCM)
}

func TestRoundTripChaCha20Poly1305(t *testing.T) {
	roundTrip(t, sessionproto.WrapCipher_WRAP_CIPHER_SRTP_CHACHA20_POLY1305)
}

// A non-random sentinel makes the "wire does not leak plaintext" check
// reliable even for small payload sizes where random bytes would
// coincidentally appear in the ciphertext.
func TestSealHidesPayload(t *testing.T) {
	client, _ := newPair(t, sessionproto.WrapCipher_WRAP_CIPHER_SRTP_AES_256_GCM)
	plaintext := bytes.Repeat([]byte("VKTPAYLOAD-SENTINEL!"), 50) // 1000 bytes
	wire, err := client.Seal(plaintext)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(wire, plaintext) {
		t.Fatalf("wrapped packet leaks plaintext sentinel")
	}
}

func TestRTPHeaderProgression(t *testing.T) {
	client, _ := newPair(t, sessionproto.WrapCipher_WRAP_CIPHER_SRTP_AES_256_GCM)
	payload := []byte("x")

	wire1, err := client.Seal(payload)
	if err != nil {
		t.Fatal(err)
	}
	wire2, err := client.Seal(payload)
	if err != nil {
		t.Fatal(err)
	}

	seq1 := binary.BigEndian.Uint16(wire1[2:4])
	seq2 := binary.BigEndian.Uint16(wire2[2:4])
	if seq2 != seq1+1 {
		t.Fatalf("seq did not increment: %d → %d", seq1, seq2)
	}
	ts1 := binary.BigEndian.Uint32(wire1[4:8])
	ts2 := binary.BigEndian.Uint32(wire2[4:8])
	if ts2-ts1 != tsStep {
		t.Fatalf("timestamp step = %d, want %d", ts2-ts1, tsStep)
	}
	if !bytes.Equal(wire1[8:12], wire2[8:12]) {
		t.Fatalf("SSRC changed between packets")
	}
}

func TestDirectionBit(t *testing.T) {
	client, server := newPair(t, sessionproto.WrapCipher_WRAP_CIPHER_SRTP_AES_256_GCM)
	c, ok := client.(*srtpConn)
	if !ok {
		t.Fatalf("client cipher is %T, want *srtpConn", client)
	}
	s, ok := server.(*srtpConn)
	if !ok {
		t.Fatalf("server cipher is %T, want *srtpConn", server)
	}
	if c.sessionID[0]&0x80 != 0 {
		t.Fatalf("client sessionID MSB should be 0, got 0x%02X", c.sessionID[0])
	}
	if s.sessionID[0]&0x80 == 0 {
		t.Fatalf("server sessionID MSB should be 1, got 0x%02X", s.sessionID[0])
	}
	if c.ssrc[0]&0x80 != 0 {
		t.Fatalf("client SSRC MSB should be 0, got 0x%02X", c.ssrc[0])
	}
	if s.ssrc[0]&0x80 == 0 {
		t.Fatalf("server SSRC MSB should be 1, got 0x%02X", s.ssrc[0])
	}
}

func TestOpenShortCiphertext(t *testing.T) {
	for _, selected := range []sessionproto.WrapCipher{
		sessionproto.WrapCipher_WRAP_CIPHER_SRTP_AES_256_GCM,
		sessionproto.WrapCipher_WRAP_CIPHER_SRTP_CHACHA20_POLY1305,
	} {
		_, server := newPair(t, selected)
		if _, err := server.Open(nil); err != ErrShortCiphertext {
			t.Fatalf("expected ErrShortCiphertext for empty input on %v, got %v", selected, err)
		}
		if _, err := server.Open(make([]byte, overhead-1)); err != ErrShortCiphertext {
			t.Fatalf("expected ErrShortCiphertext for short input on %v, got %v", selected, err)
		}
	}
}

func TestOpenRejectsTamperedCiphertext(t *testing.T) {
	client, server := newPair(t, sessionproto.WrapCipher_WRAP_CIPHER_SRTP_AES_256_GCM)
	plaintext := []byte("integrity test")
	wire, err := client.Seal(plaintext)
	if err != nil {
		t.Fatal(err)
	}
	wire[headerLen+1] ^= 0xFF
	if _, err := server.Open(wire); err == nil {
		t.Fatalf("Open accepted tampered ciphertext")
	}
}

func TestOpenRejectsTamperedAAD(t *testing.T) {
	client, server := newPair(t, sessionproto.WrapCipher_WRAP_CIPHER_SRTP_AES_256_GCM)
	plaintext := []byte("aad integrity")
	wire, err := client.Seal(plaintext)
	if err != nil {
		t.Fatal(err)
	}
	wire[8] ^= 0x01 // flip a bit in SSRC (AAD)
	if _, err := server.Open(wire); err == nil {
		t.Fatalf("Open accepted tampered AAD")
	}
}

func TestNoneCipherReturnsNil(t *testing.T) {
	for _, selected := range []sessionproto.WrapCipher{
		sessionproto.WrapCipher_WRAP_CIPHER_UNSPECIFIED,
		sessionproto.WrapCipher_WRAP_CIPHER_NONE,
	} {
		f, err := NewFactory(selected, mustKey(t))
		if err != nil {
			t.Fatalf("NewFactory(%v): unexpected error %v", selected, err)
		}
		if f != nil {
			t.Fatalf("NewFactory(%v): expected nil factory, got %T", selected, f)
		}
	}
}

func TestBadKeyLength(t *testing.T) {
	for _, selected := range []sessionproto.WrapCipher{
		sessionproto.WrapCipher_WRAP_CIPHER_SRTP_AES_256_GCM,
		sessionproto.WrapCipher_WRAP_CIPHER_SRTP_CHACHA20_POLY1305,
	} {
		if _, err := NewFactory(selected, make([]byte, 16)); err == nil {
			t.Fatalf("expected error for %v with 16-byte key", selected)
		}
	}
}
