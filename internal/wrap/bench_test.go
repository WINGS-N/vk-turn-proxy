package wrap

import (
	"crypto/rand"
	"testing"

	sessionproto "github.com/cacggghp/vk-turn-proxy/sessionproto"
)

var benchSink []byte

func benchCipher(b *testing.B) Cipher {
	b.Helper()
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		b.Fatal(err)
	}
	c, err := New(sessionproto.WrapCipher_WRAP_CIPHER_SRTP_AES_256_GCM, key, false)
	if err != nil {
		b.Fatal(err)
	}
	return c
}

// Seal allocates a frame per call; SealInto writes into a caller-owned buffer.
// The send path uses the latter, so this pair guards the difference.
func BenchmarkSeal(b *testing.B) {
	c := benchCipher(b)
	payload := make([]byte, 1400)
	b.ReportAllocs()
	b.SetBytes(int64(len(payload)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		out, err := c.Seal(payload)
		if err != nil {
			b.Fatal(err)
		}
		benchSink = out
	}
}

func BenchmarkSealInto(b *testing.B) {
	c := benchCipher(b)
	payload := make([]byte, 1400)
	dst := make([]byte, overhead+len(payload))
	b.ReportAllocs()
	b.SetBytes(int64(len(payload)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		out, err := c.SealInto(dst, payload)
		if err != nil {
			b.Fatal(err)
		}
		benchSink = out
	}
}

// SealInto with the payload already staged behind the header, which is what a
// pooled buffer with headroom gives: the payload copy disappears too.
func BenchmarkSealIntoHeadroom(b *testing.B) {
	c := benchCipher(b)
	frame := make([]byte, overhead+1400)
	b.ReportAllocs()
	b.SetBytes(1400)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		out, err := c.SealInto(frame, frame[headerLen:headerLen+1400])
		if err != nil {
			b.Fatal(err)
		}
		benchSink = out
	}
}

func BenchmarkOpen(b *testing.B) {
	c := benchCipher(b)
	sealed, err := c.Seal(make([]byte, 1400))
	if err != nil {
		b.Fatal(err)
	}
	wire := make([]byte, len(sealed))
	b.ReportAllocs()
	b.SetBytes(1400)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		copy(wire, sealed)
		out, openErr := c.Open(wire)
		if openErr != nil {
			b.Fatal(openErr)
		}
		benchSink = out
	}
}

func BenchmarkOpenInPlace(b *testing.B) {
	c := benchCipher(b)
	sealed, err := c.Seal(make([]byte, 1400))
	if err != nil {
		b.Fatal(err)
	}
	wire := make([]byte, len(sealed))
	b.ReportAllocs()
	b.SetBytes(1400)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		copy(wire, sealed)
		out, openErr := c.OpenInPlace(wire)
		if openErr != nil {
			b.Fatal(openErr)
		}
		benchSink = out
	}
}

// The scratch buffer the receive path needs per datagram, allocated versus
// taken from the pool StatefulConn now keeps.
func BenchmarkReceiveScratchAlloc(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		buf := make([]byte, readBufSize)
		buf[0] = byte(i)
		benchSink = buf
	}
}

func BenchmarkReceiveScratchPooled(b *testing.B) {
	conn := &StatefulConn{}
	*conn = *NewStateful(nil)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ptr, ok := conn.readBufs.Get().(*[]byte)
		if !ok {
			b.Fatal("pool returned an unexpected type")
		}
		(*ptr)[0] = byte(i)
		benchSink = *ptr
		conn.readBufs.Put(ptr)
	}
}

// The send path draws its scratch from a pool that several relay goroutines hit
// at once, so misses are normal and the size of a miss is what matters. This
// covers the miss: a fresh buffer plus a sealed frame.
func BenchmarkWriteScratchMiss(b *testing.B) {
	c := benchCipher(b)
	payload := make([]byte, 1400)
	b.ReportAllocs()
	b.SetBytes(int64(len(payload)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		buf := make([]byte, writeBufSize)
		out, err := c.SealInto(buf, payload)
		if err != nil {
			b.Fatal(err)
		}
		benchSink = out
	}
}

// What the same miss cost while the pool handed out 64 KiB buffers.
func BenchmarkWriteScratchMissOversized(b *testing.B) {
	c := benchCipher(b)
	payload := make([]byte, 1400)
	b.ReportAllocs()
	b.SetBytes(int64(len(payload)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		buf := make([]byte, readBufSize)
		out, err := c.SealInto(buf, payload)
		if err != nil {
			b.Fatal(err)
		}
		benchSink = out
	}
}
