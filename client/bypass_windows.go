//go:build windows

package main

import (
	"sync"
	"syscall"

	"golang.org/x/sys/windows"
)

// Winsock options that force a socket's outgoing interface, regardless of the routing
// table. Not always exported by x/sys/windows. IP_UNICAST_IF takes the interface index
// in network byte order; IPV6_UNICAST_IF takes it in host byte order.
const (
	sockIPUnicastIF   = 31
	sockIPv6UnicastIF = 31
)

var (
	physOnce sync.Once
	physIf4  uint32
	physIf6  uint32
)

// physicalInterfaces returns the interface indices of the best route to the public
// internet for IPv4/IPv6, cached. vkturn resolves these before the tunnel is up (its
// underlay sockets are created at Configure, ahead of the WireGuard interface), so the
// best route is the real physical link, not the tunnel.
func physicalInterfaces() (uint32, uint32) {
	physOnce.Do(func() {
		physIf4 = bestInterface(&windows.SockaddrInet4{Addr: [4]byte{8, 8, 8, 8}})
		physIf6 = bestInterface(&windows.SockaddrInet6{Addr: [16]byte{0x20, 0x01, 0x48, 0x60, 0x48, 0x60, 0, 0, 0, 0, 0, 0, 0, 0, 0x88, 0x88}})
	})
	return physIf4, physIf6
}

func bestInterface(sa windows.Sockaddr) uint32 {
	var idx uint32
	if err := windows.GetBestInterfaceEx(sa, &idx); err != nil {
		return 0
	}
	return idx
}

func htonl(v uint32) uint32 {
	return (v&0xff)<<24 | (v&0xff00)<<8 | (v&0xff0000)>>8 | (v>>24)&0xff
}

// pinFDToPhysical forces the socket's egress onto the physical interface so it bypasses
// the full-tunnel default route. It is the Windows analogue of the Linux fwmark bypass
// for vkturn's underlay: with 0.0.0.0/0 routed into the tunnel, vkturn's traffic to the
// VK TURN relays would otherwise loop back into the tunnel it is itself carrying. The
// wrong-family setsockopt fails harmlessly and is ignored.
func pinFDToPhysical(fd uintptr) {
	if4, if6 := physicalInterfaces()
	h := windows.Handle(fd)
	if if4 != 0 {
		_ = windows.SetsockoptInt(h, windows.IPPROTO_IP, sockIPUnicastIF, int(htonl(if4)))
	}
	if if6 != 0 {
		_ = windows.SetsockoptInt(h, windows.IPPROTO_IPV6, sockIPv6UnicastIF, int(if6))
	}
}

// pinConnToPhysical pins an already-created socket-backed conn to the physical interface.
func pinConnToPhysical(conn any) {
	sc, ok := conn.(interface {
		SyscallConn() (syscall.RawConn, error)
	})
	if !ok {
		return
	}
	if raw, err := sc.SyscallConn(); err == nil {
		_ = raw.Control(pinFDToPhysical)
	}
}
