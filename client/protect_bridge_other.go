//go:build !linux && !windows

package main

import "syscall"

// protectBridge is a no-op off Linux. The protect mechanism marks the client's underlay
// sockets to bypass the tunnel via a privileged helper over a Unix socket (SCM_RIGHTS fd
// passing), which is Linux-only. On other platforms the tunnel bypass is arranged by the
// host app's data plane instead, so the bridge does nothing.
type protectBridge struct{}

// newProtectBridge always returns a disabled (nil) bridge off Linux.
func newProtectBridge(socketName string) (*protectBridge, error) {
	return nil, nil
}

func (b *protectBridge) Close() error { return nil }

// Control is the net.Dialer Control hook; it is a no-op when the bridge is disabled.
func (b *protectBridge) Control(network, address string, rawConn syscall.RawConn) error {
	return nil
}
