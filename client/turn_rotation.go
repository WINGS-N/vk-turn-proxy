package main

import (
	"errors"
	"sync"
	"sync/atomic"
	"time"
)

const turnServerCooldown = 30 * time.Second

var (
	streamServerOffsets sync.Map // map[int]*atomic.Uint64
	turnServerCooldowns sync.Map // map[string]*atomic.Int64
)

func getStreamServerOffset(streamID int) uint64 {
	v, _ := streamServerOffsets.LoadOrStore(streamID, &atomic.Uint64{})
	return v.(*atomic.Uint64).Load() //nolint:errcheck // sync.Map value type is invariant by construction
}

func rotateStreamServer(streamID int) uint64 {
	v, _ := streamServerOffsets.LoadOrStore(streamID, &atomic.Uint64{})
	return v.(*atomic.Uint64).Add(1) //nolint:errcheck // sync.Map value type is invariant by construction
}

func markTURNServerCooldown(addr string) {
	if addr == "" {
		return
	}
	v, _ := turnServerCooldowns.LoadOrStore(addr, &atomic.Int64{})
	v.(*atomic.Int64).Store(time.Now().Add(turnServerCooldown).UnixNano()) //nolint:errcheck // sync.Map value type is invariant by construction
}

func isTURNServerAvailable(addr string) bool {
	v, ok := turnServerCooldowns.Load(addr)
	if !ok {
		return true
	}
	return time.Now().UnixNano() >= v.(*atomic.Int64).Load() //nolint:errcheck // sync.Map value type is invariant by construction
}

func pickStreamServerAddr(streamID int, addrs []string) string {
	if len(addrs) == 0 {
		return ""
	}
	if len(addrs) == 1 {
		return addrs[0]
	}
	start := (uint64(streamID) + getStreamServerOffset(streamID)) % uint64(len(addrs))
	for i := uint64(0); i < uint64(len(addrs)); i++ {
		idx := (start + i) % uint64(len(addrs))
		addr := addrs[idx]
		if isTURNServerAvailable(addr) {
			return addr
		}
	}
	return addrs[start]
}

type turnSetupError struct {
	addr string
	err  error
}

func (e *turnSetupError) Error() string { return e.err.Error() }
func (e *turnSetupError) Unwrap() error { return e.err }

func newTurnSetupError(addr string, err error) error {
	return &turnSetupError{addr: addr, err: err}
}

func turnSetupAddr(err error) (string, bool) {
	var setupErr *turnSetupError
	if errors.As(err, &setupErr) && setupErr.addr != "" {
		return setupErr.addr, true
	}
	return "", false
}
