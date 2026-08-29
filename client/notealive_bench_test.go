package main

import (
	"testing"
	"time"
)

// Liveness is stamped on every datagram in both directions. These price it as it
// stands - going through EnsureStream, which takes the runtime lock - against
// stamping a stream handle the worker already holds.

func benchRuntime() *sessionRuntime {
	runtime := &sessionRuntime{streams: map[byte]*streamRuntime{}}
	runtime.EnsureStream(0)
	return runtime
}

func BenchmarkNoteAliveViaLock(b *testing.B) {
	runtime := benchRuntime()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		runtime.NoteInbound(0, 1400)
	}
}

func BenchmarkNoteAliveViaLockContended(b *testing.B) {
	runtime := benchRuntime()
	for id := byte(1); id < 8; id++ {
		runtime.EnsureStream(id)
	}
	b.ReportAllocs()
	b.ResetTimer()
	var next byte
	b.RunParallel(func(pb *testing.PB) {
		id := next % 8
		next++
		for pb.Next() {
			runtime.NoteInbound(id, 1400)
		}
	})
}

func BenchmarkNoteAliveViaHandle(b *testing.B) {
	runtime := benchRuntime()
	stream := runtime.EnsureStream(0)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		stream.lastAliveAt.Store(time.Now().UnixMilli())
	}
}
