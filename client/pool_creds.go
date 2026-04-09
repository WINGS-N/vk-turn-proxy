package main

import (
	"errors"
	"log"
	"strings"
	"sync"
	"time"
)

type turnCred struct {
	user string
	pass string
	addr string
}

type pooledGetCredsFunc func(string, bool) (string, string, string, error)

type adaptivePoolConfig struct {
	minSize            int
	maxSize            int
	streamsPerIdentity int
}

const (
	backgroundPoolRetryCooldown           = 2 * time.Minute
	defaultAdaptivePoolStreamsPerIdentity = 4
)

func normalizeAdaptivePoolConfig(minSize, maxSize, streamsPerIdentity, configuredStreams int) adaptivePoolConfig {
	if configuredStreams < 1 {
		configuredStreams = 1
	}
	if minSize < 1 {
		minSize = 1
	}
	if maxSize < 1 {
		maxSize = configuredStreams
	}
	if maxSize > configuredStreams {
		maxSize = configuredStreams
	}
	if maxSize < minSize {
		maxSize = minSize
	}
	if streamsPerIdentity < 1 {
		streamsPerIdentity = defaultAdaptivePoolStreamsPerIdentity
	}
	return adaptivePoolConfig{
		minSize:            minSize,
		maxSize:            maxSize,
		streamsPerIdentity: streamsPerIdentity,
	}
}

func (config adaptivePoolConfig) targetPoolSize() int {
	activeStreams := max(0, int(connectedStreams.Load()))
	requiredStreams := max(1, activeStreams+1)
	desiredSize := ceilDiv(requiredStreams, config.streamsPerIdentity)
	if desiredSize < config.minSize {
		desiredSize = config.minSize
	}
	if desiredSize > config.maxSize {
		desiredSize = config.maxSize
	}
	return desiredSize
}

func ceilDiv(value, divisor int) int {
	if divisor <= 0 {
		return value
	}
	return (value + divisor - 1) / divisor
}

func poolCreds(f pooledGetCredsFunc, poolSize int) getCredsFunc {
	fixedPoolSize := max(1, poolSize)
	return poolCredsDynamic(f, func() int {
		return fixedPoolSize
	})
}

func poolCredsAdaptive(f pooledGetCredsFunc, config adaptivePoolConfig) getCredsFunc {
	return poolCredsDynamic(f, config.targetPoolSize)
}

func poolCredsDynamic(f pooledGetCredsFunc, targetPoolSize func() int) getCredsFunc {
	type poolState struct {
		mu                    sync.Mutex
		cond                  *sync.Cond
		pool                  []turnCred
		createdAt             time.Time
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
		if !state.createdAt.IsZero() && time.Since(state.createdAt) > 10*time.Minute {
			state.pool = nil
			state.createdAt = time.Time{}
			state.idx = 0
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
			if existing.user == cred.user && existing.pass == cred.pass && existing.addr == cred.addr {
				return false
			}
		}
		state.pool = append(state.pool, cred)
		state.createdAt = time.Now()
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

			user, pass, addr, err := f(link, false)
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
			added := appendIfNewLocked(turnCred{user: user, pass: pass, addr: addr})
			currentSize := len(state.pool)
			desiredSize := desiredPoolSize()
			state.backgroundRetryAfter = time.Time{}
			trimPoolToDesiredLocked()
			state.mu.Unlock()

			if added {
				log.Printf("Registered background TURN identity %d/%d", currentSize, desiredSize)
			}
		}()
	}

	return func(link string) (string, string, string, error) {
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
				return cred.user, cred.pass, cred.addr, nil
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
					return cred.user, cred.pass, cred.addr, nil
				}
				state.mu.Unlock()
				continue
			}

			state.foregroundFillRunning = true
			state.mu.Unlock()

			user, pass, addr, err := f(link, true)

			state.mu.Lock()
			state.foregroundFillRunning = false
			if err == nil {
				_ = appendIfNewLocked(turnCred{user: user, pass: pass, addr: addr})
				currentSize := len(state.pool)
				desiredSize = desiredPoolSize()
				state.backgroundRetryAfter = time.Time{}
				trimPoolToDesiredLocked()
				state.cond.Broadcast()
				state.idx++
				state.mu.Unlock()
				log.Printf("Registered primary TURN identity %d/%d", currentSize, desiredSize)
				if currentSize < desiredSize {
					startBackgroundFill(link)
				}
				return user, pass, addr, nil
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
				return cred.user, cred.pass, cred.addr, nil
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
