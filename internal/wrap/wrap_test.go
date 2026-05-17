package wrap

import (
	"bytes"
	"crypto/rand"
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

func roundTrip(t *testing.T, selected sessionproto.WrapCipher) {
	t.Helper()
	key := mustKey(t)
	c, err := New(selected, key)
	if err != nil {
		t.Fatalf("New(%v): %v", selected, err)
	}
	if c == nil {
		t.Fatalf("New(%v) returned nil cipher", selected)
	}

	for _, n := range []int{0, 1, 16, 1500, 65535} {
		plaintext := make([]byte, n)
		if _, err := rand.Read(plaintext); err != nil {
			t.Fatalf("rand: %v", err)
		}
		sealed, err := c.Seal(plaintext)
		if err != nil {
			t.Fatalf("Seal n=%d: %v", n, err)
		}
		if len(sealed) != n+c.Overhead() {
			t.Fatalf("Seal length mismatch n=%d: got %d want %d", n, len(sealed), n+c.Overhead())
		}
		opened, err := c.Open(sealed)
		if err != nil {
			t.Fatalf("Open n=%d: %v", n, err)
		}
		if !bytes.Equal(plaintext, opened) {
			t.Fatalf("round-trip mismatch n=%d", n)
		}
	}
}

func TestRoundTripAESCTR(t *testing.T) {
	roundTrip(t, sessionproto.WrapCipher_WRAP_CIPHER_AES_256_CTR)
}

func TestRoundTripChaCha20(t *testing.T) {
	roundTrip(t, sessionproto.WrapCipher_WRAP_CIPHER_CHACHA20_XOR)
}

func TestNonceUniqueness(t *testing.T) {
	key := mustKey(t)
	c, err := New(sessionproto.WrapCipher_WRAP_CIPHER_AES_256_CTR, key)
	if err != nil {
		t.Fatal(err)
	}
	plaintext := []byte("vk-turn obfuscation test payload — same plaintext should yield different ciphertexts")
	seen := map[string]struct{}{}
	for i := 0; i < 256; i++ {
		sealed, err := c.Seal(plaintext)
		if err != nil {
			t.Fatalf("Seal #%d: %v", i, err)
		}
		nonce := string(sealed[:NonceLen])
		if _, dup := seen[nonce]; dup {
			t.Fatalf("nonce collision after %d packets", i)
		}
		seen[nonce] = struct{}{}
	}
}

func TestOpenShortCiphertext(t *testing.T) {
	key := mustKey(t)
	for _, selected := range []sessionproto.WrapCipher{
		sessionproto.WrapCipher_WRAP_CIPHER_AES_256_CTR,
		sessionproto.WrapCipher_WRAP_CIPHER_CHACHA20_XOR,
	} {
		c, err := New(selected, key)
		if err != nil {
			t.Fatalf("New(%v): %v", selected, err)
		}
		if _, err := c.Open(nil); err != ErrShortCiphertext {
			t.Fatalf("expected ErrShortCiphertext for empty input on %v, got %v", selected, err)
		}
		if _, err := c.Open(make([]byte, NonceLen-1)); err != ErrShortCiphertext {
			t.Fatalf("expected ErrShortCiphertext for short input on %v, got %v", selected, err)
		}
	}
}

func TestOpenTamperedCiphertextHasNoAuth(t *testing.T) {
	// Without MAC, opening tampered data should NOT error — it just produces
	// garbage that the upper DTLS layer will reject. We assert exactly this:
	// no error, but the plaintext does not match the original.
	key := mustKey(t)
	c, err := New(sessionproto.WrapCipher_WRAP_CIPHER_AES_256_CTR, key)
	if err != nil {
		t.Fatal(err)
	}
	plaintext := []byte("hello, world!")
	sealed, err := c.Seal(plaintext)
	if err != nil {
		t.Fatal(err)
	}
	sealed[NonceLen+1] ^= 0xff
	opened, err := c.Open(sealed)
	if err != nil {
		t.Fatalf("Open on tampered ciphertext should succeed (no MAC), got %v", err)
	}
	if bytes.Equal(plaintext, opened) {
		t.Fatalf("tampered byte produced identical plaintext — keystream-XOR property broken")
	}
}

func TestNoneCipherReturnsNil(t *testing.T) {
	for _, selected := range []sessionproto.WrapCipher{
		sessionproto.WrapCipher_WRAP_CIPHER_UNSPECIFIED,
		sessionproto.WrapCipher_WRAP_CIPHER_NONE,
	} {
		c, err := New(selected, mustKey(t))
		if err != nil {
			t.Fatalf("New(%v): unexpected error %v", selected, err)
		}
		if c != nil {
			t.Fatalf("New(%v): expected nil cipher, got %T", selected, c)
		}
	}
}

func TestBadKeyLength(t *testing.T) {
	for _, selected := range []sessionproto.WrapCipher{
		sessionproto.WrapCipher_WRAP_CIPHER_AES_256_CTR,
		sessionproto.WrapCipher_WRAP_CIPHER_CHACHA20_XOR,
	} {
		if _, err := New(selected, make([]byte, 16)); err == nil {
			t.Fatalf("expected error for %v with 16-byte key", selected)
		}
	}
}
