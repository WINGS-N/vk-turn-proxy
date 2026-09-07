//go:build linux

package main

import (
	"net"

	"golang.org/x/sys/unix"
)

// segmentationAvailable - есть ли у платформы разгрузка UDP вообще
func segmentationAvailable() bool { return true }

// setUDPSegment сажает на сокет размер сегмента, которым ядро порежет пачку
func setUDPSegment(udp *net.UDPConn, segment int) error {
	raw, err := udp.SyscallConn()
	if err != nil {
		return err
	}
	var setErr error
	if ctlErr := raw.Control(func(fd uintptr) {
		setErr = unix.SetsockoptInt(int(fd), unix.IPPROTO_UDP, unix.UDP_SEGMENT, segment)
	}); ctlErr != nil {
		return ctlErr
	}
	return setErr
}
