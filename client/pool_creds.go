package main

import (
	"errors"
	"log"
	"strings"
	"sync"
	"time"
)

type turnCred struct {
	user            string
	pass            string
	addrs           []string
	bornAt          time.Time
	lifetime        time.Duration
	isSecondaryLink bool
}

// primaryAddr returns the canonical address for identity comparison; an empty
// addrs slice yields "" so dedup/log paths stay safe.
func (cred turnCred) primaryAddr() string {
	if len(cred.addrs) == 0 {
		return ""
	}
	return cred.addrs[0]
}

type pooledGetCredsFunc func(string, bool) (string, string, []string, time.Duration, error)

type pooledGetCredsResult func(link string, workerID int) (string, string, string, error)

const (
	backgroundPoolRetryCooldown = 2 * time.Minute
	credsRefreshSlackDuration   = 2 * time.Minute
	credsFallbackLifetime       = 10 * time.Minute
)

func ceilDiv(value, divisor int) int {
	if divisor <= 0 {
		return value
	}
	return (value + divisor - 1) / divisor
}

func (cred turnCred) effectiveLifetime() time.Duration {
	if cred.lifetime > 0 {
		return cred.lifetime
	}
	return credsFallbackLifetime
}

func (cred turnCred) expired(now time.Time) bool {
	lifetime := cred.effectiveLifetime()
	deadline := cred.bornAt.Add(lifetime - credsRefreshSlackDuration)
	return now.After(deadline)
}

func poolCreds(f pooledGetCredsFunc, poolSize int) pooledGetCredsResult {
	fixedPoolSize := max(1, poolSize)
	return poolCredsDynamic(f, func() int {
		return fixedPoolSize
	})
}

func poolCredsDynamic(f pooledGetCredsFunc, targetPoolSize func() int) pooledGetCredsResult {
	type poolState struct {
		mu                    sync.Mutex
		cond                  *sync.Cond
		pool                  []turnCred
		idx                   int
		foregroundFillRunning bool
		backgroundFillRunning bool
		backgroundRetryAfter  time.Time
	}

	state := &poolState{}
	state.cond = sync.NewCond(&state.mu)

	desiredPoolSize := func() int {
		if targetPoolSize == nil {
			return 1
		}
		return max(1, targetPoolSize())
	}

	expireIfNeededLocked := func() {
		if len(state.pool) == 0 {
			return
		}
		now := time.Now()
		filtered := state.pool[:0]
		removed := 0
		for _, cred := range state.pool {
			if cred.expired(now) {
				removed++
				continue
			}
			filtered = append(filtered, cred)
		}
		if removed > 0 {
			state.pool = append([]turnCred(nil), filtered...)
			if len(state.pool) == 0 {
				state.idx = 0
			} else {
				state.idx %= len(state.pool)
			}
			log.Printf("TURN identity pool: expired %d stale entries (remaining: %d)", removed, len(state.pool))
		}
	}

	trimPoolToDesiredLocked := func() {
		desiredSize := desiredPoolSize()
		if len(state.pool) <= desiredSize {
			return
		}
		state.pool = append([]turnCred(nil), state.pool[:desiredSize]...)
		if len(state.pool) == 0 {
			state.idx = 0
			return
		}
		state.idx %= len(state.pool)
	}

	appendIfNewLocked := func(cred turnCred) bool {
		for _, existing := range state.pool {
			if existing.user == cred.user && existing.pass == cred.pass && existing.primaryAddr() == cred.primaryAddr() {
				return false
			}
		}
		state.pool = append(state.pool, cred)
		return true
	}

	startBackgroundFill := func(link string) {
		state.mu.Lock()
		expireIfNeededLocked()
		trimPoolToDesiredLocked()
		desiredSize := desiredPoolSize()
		if state.backgroundFillRunning || len(state.pool) == 0 || len(state.pool) >= desiredSize {
			state.mu.Unlock()
			return
		}
		if !state.backgroundRetryAfter.IsZero() && time.Now().Before(state.backgroundRetryAfter) {
			state.mu.Unlock()
			return
		}
		state.backgroundFillRunning = true
		state.mu.Unlock()

		go func() {
			defer func() {
				state.mu.Lock()
				state.backgroundFillRunning = false
				state.mu.Unlock()
			}()

			user, pass, addrs, lifetime, err := f(link, false)
			if err != nil {
				state.mu.Lock()
				state.backgroundRetryAfter = time.Now().Add(backgroundPoolRetryCooldown)
				state.mu.Unlock()
				if errors.Is(err, errCaptchaDeferredAlreadyPending) {
					log.Printf("Background TURN identity deferred, captcha prompt already pending")
					return
				}
				log.Printf("Background TURN identity unavailable, keeping existing pool")
				return
			}

			state.mu.Lock()
			added := appendIfNewLocked(turnCred{
				user:     user,
				pass:     pass,
				addrs:    addrs,
				bornAt:   time.Now(),
				lifetime: lifetime,
			})
			currentSize := len(state.pool)
			desiredSize := desiredPoolSize()
			state.backgroundRetryAfter = time.Time{}
			trimPoolToDesiredLocked()
			state.mu.Unlock()

			if added {
				log.Printf("Registered background TURN identity %d/%d (lifetime=%s)", currentSize, desiredSize, lifetime)
			}
		}()
	}

	return func(link string, workerID int) (string, string, string, error) {
		for {
			state.mu.Lock()
			expireIfNeededLocked()
			trimPoolToDesiredLocked()
			desiredSize := desiredPoolSize()

			if len(state.pool) > 0 {
				cred := state.pool[state.idx%len(state.pool)]
				currentSize := len(state.pool)
				state.idx++
				state.mu.Unlock()
				if currentSize < desiredSize {
					startBackgroundFill(link)
				}
				return cred.user, cred.pass, pickStreamServerAddr(workerID, cred.addrs), nil
			}

			if state.foregroundFillRunning {
				for len(state.pool) == 0 && state.foregroundFillRunning {
					state.cond.Wait()
				}
				if len(state.pool) > 0 {
					cred := state.pool[state.idx%len(state.pool)]
					currentSize := len(state.pool)
					state.idx++
					state.mu.Unlock()
					if currentSize < desiredSize {
						startBackgroundFill(link)
					}
					return cred.user, cred.pass, pickStreamServerAddr(workerID, cred.addrs), nil
				}
				state.mu.Unlock()
				continue
			}

			state.foregroundFillRunning = true
			state.mu.Unlock()

			user, pass, addrs, lifetime, err := f(link, true)

			state.mu.Lock()
			state.foregroundFillRunning = false
			if err == nil {
				_ = appendIfNewLocked(turnCred{
					user:     user,
					pass:     pass,
					addrs:    addrs,
					bornAt:   time.Now(),
					lifetime: lifetime,
				})
				currentSize := len(state.pool)
				desiredSize = desiredPoolSize()
				state.backgroundRetryAfter = time.Time{}
				trimPoolToDesiredLocked()
				state.cond.Broadcast()
				state.idx++
				state.mu.Unlock()
				log.Printf("Registered primary TURN identity %d/%d (lifetime=%s)", currentSize, desiredSize, lifetime)
				if currentSize < desiredSize {
					startBackgroundFill(link)
				}
				return user, pass, pickStreamServerAddr(workerID, addrs), nil
			}

			state.cond.Broadcast()
			if len(state.pool) > 0 {
				cred := state.pool[state.idx%len(state.pool)]
				currentSize := len(state.pool)
				state.idx++
				state.mu.Unlock()
				log.Printf("Primary TURN identity unavailable, reusing pooled identity")
				if currentSize < desiredSize {
					startBackgroundFill(link)
				}
				return cred.user, cred.pass, pickStreamServerAddr(workerID, cred.addrs), nil
			}
			state.mu.Unlock()

			errText := strings.ToLower(err.Error())
			if strings.Contains(errText, "captcha") {
				log.Printf("Primary TURN identity still awaits user captcha")
			} else {
				log.Printf("Primary TURN identity unavailable")
			}
			return "", "", "", err
		}
	}
}
