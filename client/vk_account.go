package main

// VK account auth mode (stdin creds flow).
//
// In this mode the relay does NOT fetch the VK call-join page itself. Instead it
// asks the host app to open the page in its own WebView (which already carries
// the user's VK session in its CookieManager), let the user sign in and join the
// call, and intercept the VK TURN credentials there. The app then delivers those
// creds back to this relay over STDIN as a single JSON line.
//
// When creds are needed for a join hash the relay emits a
// vk_account_auth_required PROXY_EVENT carrying the full desktop join URL
// (https://vk.com/call/join/<hash>) and blocks until the app delivers the creds
// on stdin, cancels, or the wait times out. The intercepted creds are normalized
// to the same host:port address shape the anonymous path returns so the rest of
// the connection code is unchanged. The default anonymous flow in
// getVkCredsWithFallback is left untouched.
//
// Protocol (JSONL, one JSON object per line):
//   relay -> app, STDOUT PROXY_EVENT:
//     on needing creds:  {"type":"vk_account_auth_required","link":"https://vk.com/call/join/<hash>"}
//     on creds received: {"type":"vk_account_auth_complete"}
//     on failure/cancel: {"type":"vk_account_auth_failed","reason":"..."}
//   app -> relay, STDIN one JSON line:
//     creds:  {"type":"vk_account_creds","link":"<link>","username":"<u>","credential":"<p>","urls":["url1","url2"]}
//     cancel: {"type":"vk_account_creds","link":"<link>","cancel":true}
//
// The relay only READS stdin (line by line) and ignores blank / non-JSON /
// other-type lines, so any other stdout/stderr usage is unaffected.

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// vkAccountAuthEvent is emitted on the shared PROXY_EVENT channel to drive the
// host app through the stdin VK account auth flow.
type vkAccountAuthEvent struct {
	Type   string `json:"type"`
	Link   string `json:"link,omitempty"`
	Reason string `json:"reason,omitempty"`
}

// vkAccountCredsLine is a single STDIN line delivered by the host app. A
// non-cancel line carries the intercepted creds; a cancel line aborts the wait.
type vkAccountCredsLine struct {
	Type       string   `json:"type"`
	Link       string   `json:"link"`
	Username   string   `json:"username"`
	Credential string   `json:"credential"`
	URLs       []string `json:"urls"`
	Cancel     bool     `json:"cancel"`
}

const (
	accountAuthWaitTimeout = 5 * time.Minute
	accountMaxWorkers      = 4
)

// vkAccountJoinHost is the host the join link is built against. We use the
// desktop vk.com host because the m.vk.com mobile layout does not support
// joining a call.
const vkAccountJoinHost = "vk.com"

// vkJoinURLForHash builds the canonical VK call-join page URL for a join hash.
func vkJoinURLForHash(hash string) string {
	return "https://" + vkAccountJoinHost + "/call/join/" + hash
}

// vkAuthMode is the active VK auth mode: "account" or "anonymous".
var (
	vkAuthModeMu sync.RWMutex
	vkAuthMode   = "anonymous"
)

func setVkAuthMode(mode string) {
	mode = strings.ToLower(strings.TrimSpace(mode))
	if mode != "account" {
		mode = "anonymous"
	}
	vkAuthModeMu.Lock()
	vkAuthMode = mode
	vkAuthModeMu.Unlock()
}

func getVkAuthMode() string {
	vkAuthModeMu.RLock()
	defer vkAuthModeMu.RUnlock()
	return vkAuthMode
}

// injectedTurnCreds is a credentials set delivered by the host app.
type injectedTurnCreds struct {
	user  string
	pass  string
	addrs []string
}

var (
	injectedCredsMu     sync.Mutex
	injectedCredsByLink = make(map[string]injectedTurnCreds)
	// accountAuths maps a link to the single shared in-flight auth for that link.
	// All workers asking for the same link share one accountAuth so the
	// vk_account_auth_required event is emitted exactly once and every waiter is
	// released together when creds arrive. A non-nil entry IS the in-flight
	// guard: while it exists an auth for that link is outstanding and no new
	// event is emitted; it is cleared when the auth resolves or fails.
	accountAuths = make(map[string]*accountAuth)
)

// accountAuth is the shared per-link auth coordination object. The first worker
// to ask for a given link creates it (and so emits the event and reports the
// auth complete/failed terminal events); concurrent and subsequent workers for
// the same link receive the SAME *accountAuth and wait on the broadcast done
// channel instead of emitting again. Sharing one pointer means every waiter
// reads the same published res after done is observed closed.
type accountAuth struct {
	// done is closed exactly once when the auth resolves (creds) or fails
	// (cancel/timeout/abort). Closing broadcasts the result to every waiter.
	done chan struct{}
	// res holds the result published just before done is closed; it is safe to
	// read after done is observed closed.
	res accountCredsResult
}

// accountAuthHandle wraps a shared *accountAuth with a per-caller leader flag.
// Only the leader (the caller that created the underlying auth) emits the
// vk_account_auth_required / _complete / _failed events and clears the in-flight
// guard, so those happen once per link.
type accountAuthHandle struct {
	auth   *accountAuth
	leader bool
}

// accountAuthPending counts in-flight fetchAccountVkCreds waits. While > 0 a VK
// account sign-in is open in the app's WebView (which can take minutes); the
// session establishment timeout (waitForReady) must NOT count that wait as a
// session failure, mirroring the existing isCaptchaPending guard. It is a
// counter (not a bool) so concurrent account workers compose correctly.
var accountAuthPending atomic.Int32

// beginAccountAuthWait/endAccountAuthWait bracket a fetchAccountVkCreds wait.
func beginAccountAuthWait() {
	accountAuthPending.Add(1)
}

func endAccountAuthWait() {
	accountAuthPending.Add(-1)
}

// isAccountAuthPending reports whether at least one VK account auth wait is open.
func isAccountAuthPending() bool {
	return accountAuthPending.Load() > 0
}

// accountCredsResult is delivered to a per-link waiter by the stdin reader.
type accountCredsResult struct {
	creds injectedTurnCreds
	err   error
}

func cloneAddrs(s []string) []string {
	if len(s) == 0 {
		return nil
	}
	out := make([]string, len(s))
	copy(out, s)
	return out
}

// turnURLsToAddresses normalizes turn:/turns: URLs into host:port addresses,
// matching the shape produced by the anonymous path in getVkCredsWithFallback.
func turnURLsToAddresses(urls []string) []string {
	var addresses []string
	for _, raw := range urls {
		u := strings.TrimSpace(raw)
		if u == "" {
			continue
		}
		clean := strings.Split(u, "?")[0]
		address := strings.TrimPrefix(strings.TrimPrefix(clean, "turn:"), "turns:")
		address = strings.TrimSpace(address)
		if address != "" {
			addresses = append(addresses, address)
		}
	}
	return addresses
}

func injectTurnCreds(link, user, pass string, urls []string) {
	link = strings.TrimSpace(link)
	addresses := turnURLsToAddresses(urls)
	if link == "" || user == "" || pass == "" || len(addresses) == 0 {
		return
	}
	injectedCredsMu.Lock()
	injectedCredsByLink[link] = injectedTurnCreds{
		user:  user,
		pass:  pass,
		addrs: cloneAddrs(addresses),
	}
	injectedCredsMu.Unlock()
}

func getInjectedTurnCreds(link string) (user, pass string, urls []string, ok bool) {
	link = strings.TrimSpace(link)
	injectedCredsMu.Lock()
	creds, exists := injectedCredsByLink[link]
	injectedCredsMu.Unlock()
	if !exists {
		return "", "", nil, false
	}
	return creds.user, creds.pass, cloneAddrs(creds.addrs), true
}

// acquireAccountAuth returns a handle to the shared in-flight auth for link,
// creating the auth if none is outstanding. handle.leader is true only for the
// caller that created the auth; that caller must emit the
// vk_account_auth_required event and is responsible for the terminal event and
// clearing the guard. All other callers attach to the same *accountAuth and
// only wait on auth.done.
func acquireAccountAuth(link string) accountAuthHandle {
	injectedCredsMu.Lock()
	defer injectedCredsMu.Unlock()
	if a := accountAuths[link]; a != nil {
		// An auth for this link is already in flight: share it, do not re-emit.
		return accountAuthHandle{auth: a, leader: false}
	}
	a := &accountAuth{done: make(chan struct{})}
	accountAuths[link] = a
	return accountAuthHandle{auth: a, leader: true}
}

// clearAccountAuth removes the in-flight guard for link if it still points at
// the given auth, so a genuinely new attempt can re-emit. Only the leader calls
// this, on resolve or failure.
func clearAccountAuth(link string, a *accountAuth) {
	injectedCredsMu.Lock()
	if accountAuths[link] == a {
		delete(accountAuths, link)
	}
	injectedCredsMu.Unlock()
}

// resolveAccountAuth publishes res to the shared auth for link and broadcasts it
// to every waiter by closing done. The in-flight guard is also dropped here so
// the link entry does not linger past the resolution. It is safe to call more
// than once for the same link; only the first close takes effect.
func resolveAccountAuth(link string, res accountCredsResult) {
	injectedCredsMu.Lock()
	a := accountAuths[link]
	if a != nil {
		delete(accountAuths, link)
	}
	injectedCredsMu.Unlock()
	if a == nil {
		return
	}
	select {
	case <-a.done:
		// Already resolved; nothing to broadcast.
	default:
		a.res = res
		close(a.done)
	}
}

// StartAccountCredsStdinReader starts a goroutine that reads os.Stdin line by
// line and dispatches vk_account_creds lines to the per-link waiters. It is
// started from main() ONLY in account mode. Blank lines, non-JSON lines and
// lines whose type is not "vk_account_creds" are ignored, so any other use of
// stdin/stdout by the host is unaffected (we only READ stdin).
func StartAccountCredsStdinReader(ctx context.Context) {
	go func() {
		scanner := bufio.NewScanner(os.Stdin)
		// VK TURN creds lines can carry several turn: URLs; allow a generous line
		// size so a long JSON object is not truncated.
		scanner.Buffer(make([]byte, 0, 64*1024), 1<<20)
		for scanner.Scan() {
			select {
			case <-ctx.Done():
				return
			default:
			}
			line := strings.TrimSpace(scanner.Text())
			if line == "" || line[0] != '{' {
				continue
			}
			var msg vkAccountCredsLine
			if err := json.Unmarshal([]byte(line), &msg); err != nil {
				continue
			}
			if msg.Type != "vk_account_creds" {
				continue
			}
			link := strings.TrimSpace(msg.Link)
			if link == "" {
				continue
			}
			if msg.Cancel {
				log.Printf("[VK Auth] account creds cancel received for link %s", link)
				resolveAccountAuth(link, accountCredsResult{err: fmt.Errorf("VK account auth cancelled by app")})
				continue
			}
			addresses := turnURLsToAddresses(msg.URLs)
			if msg.Username == "" || msg.Credential == "" || len(addresses) == 0 {
				log.Printf("[VK Auth] ignoring incomplete account creds line for link %s", link)
				continue
			}
			injectTurnCreds(link, msg.Username, msg.Credential, msg.URLs)
			resolveAccountAuth(link, accountCredsResult{creds: injectedTurnCreds{
				user:  msg.Username,
				pass:  msg.Credential,
				addrs: cloneAddrs(addresses),
			}})
			log.Printf("[VK Auth] received account TURN creds for link %s (urls=%d)", link, len(addresses))
		}
		if err := scanner.Err(); err != nil {
			log.Printf("[VK Auth] account creds stdin reader stopped: %s", err)
		}
	}()
}

// fetchAccountVkCreds returns ready TURN creds for a VK join hash in account
// mode. If creds are not cached yet, it emits a vk_account_auth_required
// PROXY_EVENT carrying the desktop join URL (the host app opens it in a WebView,
// signs in, joins the call and intercepts the VK turn_server creds) and blocks
// until the app delivers the creds on stdin, the app cancels, or the wait times
// out. The returned tuple matches the host:port address shape used by the
// anonymous path so callers stay unchanged.
func fetchAccountVkCreds(ctx context.Context, link string, resolver *protectedResolver, userAgent string, streamID int) (string, string, []string, error) {
	_ = resolver
	_ = userAgent
	link = strings.TrimSpace(link)
	if link == "" {
		return "", "", nil, fmt.Errorf("empty VK join link")
	}

	if user, pass, addrs, ok := getInjectedTurnCreds(link); ok {
		log.Printf("[STREAM %d] [VK Auth] using cached account creds (urls=%d)", streamID, len(addrs))
		return user, pass, addrs, nil
	}

	// Attach to the shared in-flight auth for this link. Only the leader (the
	// first worker for the link while no auth is outstanding) emits events; all
	// other workers wait on the same shared done channel so the
	// vk_account_auth_required event (and the WebView open it drives) happens
	// once per link. The acquire/emit pair is NOT atomic with the cache check
	// above, but the leader status from acquireAccountAuth still guarantees a
	// single emitter for any outstanding auth.
	handle := acquireAccountAuth(link)
	auth := handle.auth
	if handle.leader {
		// The leader owns the terminal event and clearing the in-flight guard so
		// a later genuinely new attempt can re-emit.
		defer clearAccountAuth(link, auth)
		joinURL := vkJoinURLForHash(link)
		emitProxyEvent(vkAccountAuthEvent{
			Type: "vk_account_auth_required",
			Link: joinURL,
		})
		log.Printf("[STREAM %d] [VK Auth] account auth required: link=%s (waiting for app to deliver creds on stdin)", streamID, joinURL)
	} else {
		log.Printf("[STREAM %d] [VK Auth] account auth already in flight for link; waiting on shared result (no re-emit)", streamID)
	}

	waitCtx, cancel := context.WithTimeout(ctx, accountAuthWaitTimeout)
	defer cancel()

	// Mark a VK account auth as in flight so the session-establishment timeout
	// (waitForReady) does not tear the session down while the user is still
	// signing in. This can take minutes; the 5-min auth wait here is bounded by
	// accountAuthWaitTimeout, not by the session ready timeout.
	beginAccountAuthWait()
	defer endAccountAuthWait()
	log.Printf("[STREAM %d] [VK Auth] waiting for account sign-in (up to %s); session ready-timeout is suspended during this wait", streamID, accountAuthWaitTimeout)

	var res accountCredsResult
	select {
	case <-auth.done:
		// Broadcast result; safe to read res after done is closed.
		res = auth.res
	case <-waitCtx.Done():
		reason := "VK account auth timeout"
		if ctx.Err() != nil {
			reason = "VK account auth aborted"
		}
		// Only the leader emits the terminal failure event so it fires once per
		// link. Publish the failure to any sibling waiters too: resolveAccountAuth
		// broadcasts via the shared done channel and drops the in-flight guard
		// (the leader's deferred clearAccountAuth is then a no-op).
		if handle.leader {
			resolveAccountAuth(link, accountCredsResult{err: fmt.Errorf("%s: %w", reason, waitCtx.Err())})
			emitProxyEvent(vkAccountAuthEvent{Type: "vk_account_auth_failed", Reason: reason})
		}
		return "", "", nil, fmt.Errorf("%s: %w", reason, waitCtx.Err())
	}

	if res.err != nil {
		if handle.leader {
			emitProxyEvent(vkAccountAuthEvent{Type: "vk_account_auth_failed", Reason: errorString(res.err)})
		}
		return "", "", nil, res.err
	}
	if handle.leader {
		emitProxyEvent(vkAccountAuthEvent{Type: "vk_account_auth_complete"})
	}
	// The stdin reader also caches via injectTurnCreds; prefer the cache.
	if user, pass, addrs, ok := getInjectedTurnCreds(link); ok {
		return user, pass, addrs, nil
	}
	return res.creds.user, res.creds.pass, cloneAddrs(res.creds.addrs), nil
}
