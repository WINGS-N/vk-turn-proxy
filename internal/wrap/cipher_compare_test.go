package wrap

import (
	"crypto/rand"
	"testing"

	sessionproto "github.com/cacggghp/vk-turn-proxy/sessionproto"
)

// AES-GCM is only cheap where the CPU has AES-NI. ChaCha20-Poly1305 needs no
// such instructions, so on an older machine the two can be worlds apart - which
// is exactly the question when picking the WRAP cipher for a given relay.
func benchSelectedCipher(b *testing.B, selected sessionproto.WrapCipher) {
	b.Helper()
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		b.Fatal(err)
	}
	cipher, err := New(selected, key, false)
	if err != nil {
		b.Fatal(err)
	}
	frame := make([]byte, overhead+1400)
	b.ReportAllocs()
	b.SetBytes(1400)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		out, sealErr := cipher.SealInto(frame, frame[headerLen:headerLen+1400])
		if sealErr != nil {
			b.Fatal(sealErr)
		}
		benchSink = out
	}
}

func BenchmarkCipherAES256GCM(b *testing.B) {
	benchSelectedCipher(b, sessionproto.WrapCipher_WRAP_CIPHER_SRTP_AES_256_GCM)
}

func BenchmarkCipherChaCha20Poly1305(b *testing.B) {
	benchSelectedCipher(b, sessionproto.WrapCipher_WRAP_CIPHER_SRTP_CHACHA20_POLY1305)
}
