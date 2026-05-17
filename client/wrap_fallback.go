package main

import (
	"sync"
	"time"
)

// Client-side WRAP fallback heuristic.
//
// WRAP wraps every datagram travelling between client and TURN relay
// endpoint. DTLS handshake runs on top of (un)wrapped bytes, so a server
// that does not speak WRAP simply cannot parse our wrapped ClientHello
// and silently drops it — there is no in-band way to "downgrade" mid-DTLS.
//
// For mode "preferred" we therefore implement a heuristic: spawn a
// watchdog when WRAP is active. If no datagram from the TURN relay is
// successfully unwrapped within wrapFallbackInboundTimeout, mark the
// server address as "WRAP unsupported" for wrapFallbackAddrTTL and tear
// the worker down. The maintain loop reconnects and the next attempt
// (within the TTL window) skips WRAP for that address.

const (
	// 5s gives DTLS time for ~3 retransmits (1s, 2s, 4s) — long enough to
	// be sure the peer is not replying, short enough that two attempts
	// (WRAP then raw) comfortably fit inside the 30s mainline bootstrap
	// budget even when TURN allocate is slow.
	wrapFallbackInboundTimeout = 5 * time.Second
	wrapFallbackAddrTTL        = 5 * time.Minute
)

var wrapDisabledAddrs sync.Map // map[string]time.Time

func wrapDisabledForAddr(addr string) bool {
	v, ok := wrapDisabledAddrs.Load(addr)
	if !ok {
		return false
	}
	at, ok := v.(time.Time)
	if !ok || time.Since(at) > wrapFallbackAddrTTL {
		wrapDisabledAddrs.Delete(addr)
		return false
	}
	return true
}

func markWrapDisabledForAddr(addr string) {
	if addr == "" {
		return
	}
	wrapDisabledAddrs.Store(addr, time.Now())
}
