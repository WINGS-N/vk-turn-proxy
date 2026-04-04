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

const backgroundPoolRetryCooldown = 2 * time.Minute

func poolCreds(f pooledGetCredsFunc, poolSize int) getCredsFunc {
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

	expireIfNeededLocked := func() {
		if !state.createdAt.IsZero() && time.Since(state.createdAt) > 10*time.Minute {
			state.pool = nil
			state.createdAt = time.Time{}
			state.idx = 0
		}
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
		if state.backgroundFillRunning || len(state.pool) == 0 || len(state.pool) >= poolSize {
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
			state.backgroundRetryAfter = time.Time{}
			state.mu.Unlock()

			if added {
				log.Printf("Registered background TURN identity %d/%d", currentSize, poolSize)
			}
		}()
	}

	return func(link string) (string, string, string, error) {
		for {
			state.mu.Lock()
			expireIfNeededLocked()

			if len(state.pool) > 0 {
				cred := state.pool[state.idx%len(state.pool)]
				state.idx++
				state.mu.Unlock()
				if len(state.pool) < poolSize {
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
					state.idx++
					state.mu.Unlock()
					if len(state.pool) < poolSize {
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
				state.backgroundRetryAfter = time.Time{}
				state.cond.Broadcast()
				state.idx++
				state.mu.Unlock()
				log.Printf("Registered primary TURN identity %d/%d", currentSize, poolSize)
				if currentSize < poolSize {
					startBackgroundFill(link)
				}
				return user, pass, addr, nil
			}

			state.cond.Broadcast()
			if len(state.pool) > 0 {
				cred := state.pool[state.idx%len(state.pool)]
				state.idx++
				state.mu.Unlock()
				log.Printf("Primary TURN identity unavailable, reusing pooled identity")
				if len(state.pool) < poolSize {
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
