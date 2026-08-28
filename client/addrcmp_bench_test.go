package main

import (
	"net"
	"sync/atomic"
	"testing"
)

// The reader checks whether the local WireGuard peer moved. Doing that by
// formatting both addresses builds two strings per datagram; comparing the parts
// touches no allocator at all.

func sameUDPAddr(a, b net.Addr) bool {
	left, ok := a.(*net.UDPAddr)
	if !ok {
		return false
	}
	right, ok := b.(*net.UDPAddr)
	if !ok {
		return false
	}
	return left.Port == right.Port && left.IP.Equal(right.IP) && left.Zone == right.Zone
}

func benchAddrs() (*atomic.Value, net.Addr) {
	stored := &atomic.Value{}
	current := &net.UDPAddr{IP: net.IPv4(10, 66, 66, 2), Port: 51820}
	stored.Store(net.Addr(current))
	incoming := net.Addr(&net.UDPAddr{IP: net.IPv4(10, 66, 66, 2), Port: 51820})
	return stored, incoming
}

func BenchmarkPeerCheckByString(b *testing.B) {
	stored, incoming := benchAddrs()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		current := stored.Load()
		if currentAddr, ok := current.(net.Addr); !ok || currentAddr.String() != incoming.String() {
			stored.Store(incoming)
		}
	}
}

func BenchmarkPeerCheckByParts(b *testing.B) {
	stored, incoming := benchAddrs()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		current := stored.Load()
		if currentAddr, ok := current.(net.Addr); !ok || !sameUDPAddr(currentAddr, incoming) {
			stored.Store(incoming)
		}
	}
}
