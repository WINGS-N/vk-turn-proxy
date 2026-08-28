package main

import (
	"strconv"
	"testing"
)

// Byte accounting runs on every datagram in every relay loop. These price it as
// it stands - one global mutex plus two string-keyed map lookups - both on a
// single stream and with several streams hammering it at once, which is the
// shape a busy relay actually has.

func benchTUI(b *testing.B, streams int) *serverTUI {
	b.Helper()
	tui := newServerTUI("127.0.0.1:0", "127.0.0.1:1", "mainline", "off")
	for i := 0; i < streams; i++ {
		key := "stream-" + strconv.Itoa(i)
		tui.registerStream(key, "turn", 1, "10.0.0.1:1", "10.66.66."+strconv.Itoa(i+2), "sess", byte(i))
	}
	return tui
}

func BenchmarkStatsSingleStream(b *testing.B) {
	tui := benchTUI(b, 1)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		tui.addStreamRx("stream-0", "10.66.66.2", 1400)
	}
}

func BenchmarkStatsContended(b *testing.B) {
	const streams = 8
	tui := benchTUI(b, streams)
	b.ReportAllocs()
	b.ResetTimer()
	var counter int64
	b.RunParallel(func(pb *testing.PB) {
		index := int(counter) % streams
		counter++
		key := "stream-" + strconv.Itoa(index)
		clientIP := "10.66.66." + strconv.Itoa(index+2)
		for pb.Next() {
			tui.addStreamRx(key, clientIP, 1400)
		}
	})
}

// The same accounting through the handle a relay loop now holds: no lock, no map
// lookup, just the atomic adds.

func BenchmarkStatsHandleSingleStream(b *testing.B) {
	tui := benchTUI(b, 1)
	counters := tui.counters("stream-0", "10.66.66.2")
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		counters.addRx(1400)
	}
}

func BenchmarkStatsHandleContended(b *testing.B) {
	const streams = 8
	tui := benchTUI(b, streams)
	handles := make([]*streamCounters, streams)
	for i := range handles {
		handles[i] = tui.counters("stream-"+strconv.Itoa(i), "10.66.66."+strconv.Itoa(i+2))
	}
	b.ReportAllocs()
	b.ResetTimer()
	var counter int64
	b.RunParallel(func(pb *testing.PB) {
		handle := handles[int(counter)%streams]
		counter++
		for pb.Next() {
			handle.addRx(1400)
		}
	})
}
