package main

import (
	"net"
	"testing"
)

func TestSameUDPPeer(t *testing.T) {
	base := &net.UDPAddr{IP: net.IPv4(10, 66, 66, 2), Port: 51820}
	cases := []struct {
		name  string
		other net.Addr
		want  bool
	}{
		{"identical", &net.UDPAddr{IP: net.IPv4(10, 66, 66, 2), Port: 51820}, true},
		{"same address written as 16 bytes", &net.UDPAddr{IP: net.IP(net.IPv4(10, 66, 66, 2).To16()), Port: 51820}, true},
		{"different port", &net.UDPAddr{IP: net.IPv4(10, 66, 66, 2), Port: 51821}, false},
		{"different host", &net.UDPAddr{IP: net.IPv4(10, 66, 66, 3), Port: 51820}, false},
		{"different zone", &net.UDPAddr{IP: net.IPv4(10, 66, 66, 2), Port: 51820, Zone: "wg0"}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := sameUDPPeer(base, tc.other); got != tc.want {
				t.Fatalf("sameUDPPeer = %v, want %v", got, tc.want)
			}
		})
	}
}

// A non-UDP address must still compare correctly rather than reporting a false
// move, which would make the reader rewrite the peer on every datagram.
func TestSameUDPPeerFallsBackForOtherAddrTypes(t *testing.T) {
	left := &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 9}
	right := &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 9}
	if !sameUDPPeer(left, right) {
		t.Fatal("equal TCP addresses reported as different")
	}
	if sameUDPPeer(left, &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 10}) {
		t.Fatal("different TCP addresses reported as equal")
	}
}
