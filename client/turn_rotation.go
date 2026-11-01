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
		claimStreamSeat(streamID, addrs[0])
		return addrs[0]
	}
	start := (uint64(streamID) + getStreamServerOffset(streamID)) % uint64(len(addrs))
	// Первый проход ищет релей и живой, и с местом; второй забывает про квоту,
	// потому что отдать стриму переполненный релей лучше, чем ничего
	for _, needRoom := range [2]bool{true, false} {
		for i := uint64(0); i < uint64(len(addrs)); i++ {
			idx := (start + i) % uint64(len(addrs))
			addr := addrs[idx]
			if !isTURNServerAvailable(addr) {
				continue
			}
			if needRoom && !turnServerHasRoom(addr) {
				continue
			}
			claimStreamSeat(streamID, addr)
			return addr
		}
	}
	claimStreamSeat(streamID, addrs[start])
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

// Квота мест на релее. ВК даёт одной ссылке звонка 20 аллокаций, и если свалить
// все стримы на один адрес, релей начнёт отказывать, пока соседние простаивают.
// Место бронируется там же, где выбирается адрес: иначе параллельные аллокации
// проскакивают мимо лимита между выбором и Allocate
const defaultTURNServerQuota = 20

var (
	turnServerQuota atomic.Int64 // 0 - у релея нет лимита
	turnServerSeats sync.Map     // map[string]*atomic.Int64, занято на адресе
	streamSeatAddrs sync.Map     // map[int]string, какое место держит стрим
)

func init() {
	turnServerQuota.Store(defaultTURNServerQuota)
}

// setTURNServerQuota задаёт лимит аллокаций на один релей; 0 снимает лимит
func setTURNServerQuota(quota int) {
	if quota < 0 {
		quota = 0
	}
	turnServerQuota.Store(int64(quota))
}

func turnServerSeatCounter(addr string) *atomic.Int64 {
	v, _ := turnServerSeats.LoadOrStore(addr, &atomic.Int64{})
	return v.(*atomic.Int64) //nolint:errcheck // sync.Map value type is invariant by construction
}

// turnServerHasRoom говорит, влезет ли ещё одна аллокация на этот релей
func turnServerHasRoom(addr string) bool {
	quota := turnServerQuota.Load()
	if quota <= 0 || addr == "" {
		return true
	}
	return turnServerSeatCounter(addr).Load() < quota
}

// claimStreamSeat переносит место стрима на addr, освобождая прежнее
func claimStreamSeat(streamID int, addr string) {
	if previous, ok := streamSeatAddrs.Load(streamID); ok {
		prevAddr := previous.(string) //nolint:errcheck // sync.Map value type is invariant by construction
		if prevAddr == addr {
			return
		}
		turnServerSeatCounter(prevAddr).Add(-1)
	}
	if addr == "" {
		streamSeatAddrs.Delete(streamID)
		return
	}
	turnServerSeatCounter(addr).Add(1)
	streamSeatAddrs.Store(streamID, addr)
}

// releaseStreamSeat отпускает место стрима: он ушёл в drain или умер
func releaseStreamSeat(streamID int) {
	claimStreamSeat(streamID, "")
}
