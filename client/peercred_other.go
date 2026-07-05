//go:build !linux

package main

import "net"

// newPeerCredListener is a no-op on non-linux (dev) builds; the unix socket's
// 0600 permissions in the app-private directory remain the access control.
func newPeerCredListener(l net.Listener, _ uint32) net.Listener {
	return l
}

// relabelSocket is a no-op off linux (SELinux only).
func relabelSocket(_, _ string) error { return nil }
