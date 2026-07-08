//go:build windows

package main

import "syscall"

// protectBridge on Windows has no privileged helper / Unix socket; instead its Control
// hook pins the dialer's sockets to the physical interface (IP_UNICAST_IF) so the
// protected underlay bypasses the full-tunnel default route, mirroring what
// pinConnToPhysical does for the directNet sockets.
type protectBridge struct{}

func newProtectBridge(socketName string) (*protectBridge, error) {
	return &protectBridge{}, nil
}

func (b *protectBridge) Close() error { return nil }

func (b *protectBridge) Control(network, address string, rawConn syscall.RawConn) error {
	if b == nil {
		return nil
	}
	// The address is a resolved host:port here (DoH, VK API/auth, DTLS control), so announce
	// it for a physical bypass route too, not just the per-socket interface pin.
	reportUnderlayDest(address)
	return rawConn.Control(pinFDToPhysical)
}
