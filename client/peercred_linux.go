//go:build linux

package main

import (
	"net"

	"golang.org/x/sys/unix"
)

// peerCredListener accepts only unix-socket peers whose UID matches allowedUID.
// libclient.so runs in the host app's process, so allowedUID is this process's
// own UID and only the app can connect.
type peerCredListener struct {
	net.Listener
	allowedUID uint32
}

func newPeerCredListener(l net.Listener, allowedUID uint32) net.Listener {
	return &peerCredListener{Listener: l, allowedUID: allowedUID}
}

func (l *peerCredListener) Accept() (net.Conn, error) {
	for {
		conn, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		uc, ok := conn.(*net.UnixConn)
		if !ok {
			_ = conn.Close()
			continue
		}
		uid, err := peerUID(uc)
		if err != nil || uid != l.allowedUID {
			_ = conn.Close()
			continue
		}
		return conn, nil
	}
}

func peerUID(conn *net.UnixConn) (uint32, error) {
	raw, err := conn.SyscallConn()
	if err != nil {
		return 0, err
	}
	var cred *unix.Ucred
	var opErr error
	if ctrlErr := raw.Control(func(fd uintptr) {
		cred, opErr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
	}); ctrlErr != nil {
		return 0, ctrlErr
	}
	if opErr != nil {
		return 0, opErr
	}
	return cred.Uid, nil
}
