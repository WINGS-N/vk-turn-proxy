//go:build windows

package main

import (
	"log"
	"net"
	"net/netip"
	"strings"
	"sync"
	"syscall"

	"golang.org/x/sys/windows"
)

var (
	physOnce sync.Once
	physIf4  uint32
	physIf6  uint32
)

// initBypass resolves and caches the physical interface indices eagerly at process start,
// before any tunnel exists. Doing it lazily on the first pinned socket is a race on a slow
// host: if the WireGuard interface comes up before vkturn opens its first underlay socket,
// GetBestInterfaceEx would pick the tunnel as the best route to 8.8.8.8 and cache THAT, so
// the bypass would then pin every underlay socket back into the tunnel it is carrying - a
// loop that makes the TURN workers drop right after connect. Calling this in main (well
// ahead of Configure and the WireGuard interface) pins the cache to the real link.
func initBypass() {
	if4, if6 := physicalInterfaces()
	log.Printf("[bypass] physical egress cached if4=%d if6=%d (pinning underlay sockets here)", if4, if6)
}

// physicalInterfaces returns the interface indices of the best route to the public
// internet for IPv4/IPv6, cached. Resolved eagerly via initBypass at startup so the best
// route is the real physical link, not a tunnel that comes up later.
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

// pinFDToPhysical is retained as the directNet Control hook but is now a no-op (see below).
func pinFDToPhysical(fd uintptr) {
	// Intentionally a no-op. IP_UNICAST_IF forces the egress interface but not the source
	// address: the route lookup still finds the tunnel's full-tunnel route and stamps the
	// tunnel's IP as the source, a martian the upstream router drops. The underlay bypass on
	// Windows is done purely by /32 routes via the physical gateway (see reportUnderlayDest
	// -> the host app's AddBypassRoute), which the WireGuard Windows client and the working
	// wg-tun.exe reference also rely on. Pinning here on top of those routes only muddied the
	// path and destabilized the TURN sockets, so it is disabled.
	_ = fd
}

// reportUnderlayDest announces a dialed underlay destination (host:port or bare IP) to the
// host app over StreamUnderlayIPs, so it can install a /32 physical-gateway bypass route.
// Only public IPv4 is reported; loopback/private/multicast are skipped.
func reportUnderlayDest(hostport string) {
	host := strings.TrimSpace(hostport)
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	ip, err := netip.ParseAddr(host)
	if err != nil || !ip.Is4() {
		return
	}
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsUnspecified() || ip.IsMulticast() || ip.IsLinkLocalUnicast() {
		return
	}
	underlayIPHub.publish(ip.String())
}

// publish records a newly pinned underlay IP and fans it out to StreamUnderlayIPs
// subscribers. Defined here because only the Windows bypass path populates the hub.
func (h *underlayIPBroadcaster) publish(ip string) {
	if ip == "" {
		return
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if _, ok := h.known[ip]; ok {
		return
	}
	h.known[ip] = struct{}{}
	log.Printf("[bypass] underlay IP %s (announcing to host app)", ip)
	for ch := range h.subs {
		select {
		case ch <- ip:
		default:
		}
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
