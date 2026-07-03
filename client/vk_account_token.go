package main

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	fhttp "github.com/bogdanfinn/fhttp"
)

// B' authorized-account TURN flow. The host app delivers the live VK web session
// cookies + matching User-Agent on a vk_cookies stdin line; this relay then mints
// the privileged web token (login.vk.com act=web_token) with its browser-
// fingerprinted fhttp client and runs the OK-infra chain, all without a visible
// WebView.
const (
	okCallsAppKey   = "CGMMEJLGDIHBABABA"
	okCallsFbDo     = "https://calls.okcdn.ru/fb.do"
	vkExecuteURL    = "https://api.vk.com/method/execute?v=5.282&client_id=6287487"
	vkWebTokenURL   = "https://login.vk.com/?act=web_token"
	vkWebTokenAppID = "6287487"
)

var (
	vkSessionMu     sync.RWMutex
	vkCookies       string
	vkUA            string
	vkCookieReadyCh = make(chan struct{})
)

func setVkCookies(cookies, ua string) {
	vkSessionMu.Lock()
	vkCookies = strings.TrimSpace(cookies)
	if strings.TrimSpace(ua) != "" {
		vkUA = strings.TrimSpace(ua)
	}
	if vkCookies != "" {
		// Wake any fetch waiting for the host app to deliver the session.
		close(vkCookieReadyCh)
		vkCookieReadyCh = make(chan struct{})
	}
	vkSessionMu.Unlock()
	persistVkSession()
}

// vkSessionFile persists the session across relay restarts; set once at startup.
var vkSessionFile string

// vkSessionReadOnly is set on the root/file-poll path: the host app owns the
// session file there (the relay runs as root, so its own write would create a
// root-owned file the app could no longer overwrite), so the relay only reads it.
var vkSessionReadOnly bool

func setVkSessionFile(path string) {
	vkSessionFile = strings.TrimSpace(path)
}

type vkSessionPersist struct {
	Cookies string `json:"cookies"`
	UA      string `json:"ua"`
}

// loadVkSessionFromFile restores a persisted VK session into memory so the relay
// keeps serving authorized TURN across its own restarts without asking the host
// app to sign in again.
func loadVkSessionFromFile() {
	if vkSessionFile == "" {
		return
	}
	data, err := os.ReadFile(vkSessionFile)
	if err != nil {
		return
	}
	var s vkSessionPersist
	if json.Unmarshal(data, &s) != nil || strings.TrimSpace(s.Cookies) == "" {
		return
	}
	vkSessionMu.Lock()
	if vkCookies == "" {
		vkCookies = strings.TrimSpace(s.Cookies)
		if strings.TrimSpace(s.UA) != "" {
			vkUA = strings.TrimSpace(s.UA)
		}
	}
	vkSessionMu.Unlock()
	log.Printf("[VK Auth] restored VK session from disk (%d cookie chars)", len(strings.TrimSpace(s.Cookies)))
}

// persistVkSession atomically writes the current session to disk for the next
// relay start to restore. Safe to call without holding vkSessionMu.
func persistVkSession() {
	if vkSessionFile == "" || vkSessionReadOnly {
		return
	}
	vkSessionMu.RLock()
	s := vkSessionPersist{Cookies: vkCookies, UA: vkUA}
	vkSessionMu.RUnlock()
	if s.Cookies == "" {
		return
	}
	data, err := json.Marshal(s)
	if err != nil {
		return
	}
	tmp := vkSessionFile + ".tmp"
	if os.WriteFile(tmp, data, 0o600) != nil {
		return
	}
	_ = os.Rename(tmp, vkSessionFile)
}

const vkSessionFilePollInterval = 3 * time.Second

// startVkSessionFilePoll watches the session file for cookies written by the host
// app on the root/kernel-WG path, where the relay's stdin is not writable so the
// usual vk_account_creds stdin line cannot be delivered. It adopts a changed
// session live and wakes any fetch blocked waiting for cookies.
func startVkSessionFilePoll(ctx context.Context) {
	if vkSessionFile == "" {
		return
	}
	vkSessionReadOnly = true
	go func() {
		ticker := time.NewTicker(vkSessionFilePollInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				adoptVkSessionFromFileIfWaiting()
			}
		}
	}()
}

func adoptVkSessionFromFileIfWaiting() {
	if vkSessionFile == "" {
		return
	}
	data, err := os.ReadFile(vkSessionFile)
	if err != nil {
		return
	}
	var s vkSessionPersist
	if json.Unmarshal(data, &s) != nil {
		return
	}
	fresh := strings.TrimSpace(s.Cookies)
	if fresh == "" {
		return
	}
	vkSessionMu.Lock()
	// Only adopt while the relay is waiting (empty jar). The relay clears vkCookies
	// before asking the app to sign in, so an empty jar means the file holds a fresh
	// delivery. A non-empty jar means the relay already has a session -- possibly
	// one it just rotated from a Set-Cookie response that the app has not yet
	// mirrored to the file -- and overwriting it from the stale file would revert
	// that rotation.
	if vkCookies != "" {
		vkSessionMu.Unlock()
		return
	}
	vkCookies = fresh
	if strings.TrimSpace(s.UA) != "" {
		vkUA = strings.TrimSpace(s.UA)
	}
	close(vkCookieReadyCh)
	vkCookieReadyCh = make(chan struct{})
	vkSessionMu.Unlock()
	log.Printf("[VK Auth] adopted VK session from disk (%d cookie chars)", len(fresh))
}

func getVkSession() (string, string, <-chan struct{}) {
	vkSessionMu.RLock()
	defer vkSessionMu.RUnlock()
	return vkCookies, vkUA, vkCookieReadyCh
}

// vkCookiesUpdateEvent pushes the relay's refreshed VK cookie jar back to the
// host app so its WebView CookieManager stays in sync with the rotated session.
type vkCookiesUpdateEvent struct {
	Type    string `json:"type"`
	Cookies string `json:"cookies"`
}

func isVkHost(host string) bool {
	return host == "vk.com" || strings.HasSuffix(host, ".vk.com")
}

// mergeVkSetCookies folds rotated Set-Cookie values from a vk.com response into
// the cached session jar so later web_token mints stay authorized without another
// app round-trip, and pushes the refreshed jar back to the host app on change.
func mergeVkSetCookies(setCookies []*fhttp.Cookie) {
	if len(setCookies) == 0 {
		return
	}
	vkSessionMu.Lock()
	pairs, order := cookiePairs(vkCookies)
	changed := false
	for _, c := range setCookies {
		if c == nil || c.Name == "" {
			continue
		}
		if c.MaxAge < 0 || (!c.Expires.IsZero() && c.Expires.Before(time.Now())) {
			if _, ok := pairs[c.Name]; ok {
				delete(pairs, c.Name)
				order = removeCookieName(order, c.Name)
				changed = true
			}
			continue
		}
		if old, ok := pairs[c.Name]; !ok || old != c.Value {
			if !ok {
				order = append(order, c.Name)
			}
			pairs[c.Name] = c.Value
			changed = true
		}
	}
	if !changed {
		vkSessionMu.Unlock()
		return
	}
	vkCookies = serializeCookies(pairs, order)
	updated := vkCookies
	vkSessionMu.Unlock()
	persistVkSession()
	log.Printf("[VK Auth] merged rotated VK cookies from response")
	// The event path stays, but with the AppControl IPC active the cookie value
	// must not reach stdout; the app pulls it via GetVKCookies instead.
	if appControlActive.Load() {
		updated = ""
	}
	emitProxyEvent(vkCookiesUpdateEvent{Type: "vk_cookies_update", Cookies: updated})
}

func cookiePairs(s string) (map[string]string, []string) {
	pairs := make(map[string]string)
	var order []string
	for _, part := range strings.Split(s, ";") {
		part = strings.TrimSpace(part)
		eq := strings.IndexByte(part, '=')
		if eq <= 0 {
			continue
		}
		name := strings.TrimSpace(part[:eq])
		if _, ok := pairs[name]; !ok {
			order = append(order, name)
		}
		pairs[name] = strings.TrimSpace(part[eq+1:])
	}
	return pairs, order
}

func serializeCookies(pairs map[string]string, order []string) string {
	var b strings.Builder
	for _, name := range order {
		val, ok := pairs[name]
		if !ok {
			continue
		}
		if b.Len() > 0 {
			b.WriteString("; ")
		}
		b.WriteString(name)
		b.WriteByte('=')
		b.WriteString(val)
	}
	return b.String()
}

func removeCookieName(order []string, name string) []string {
	out := order[:0]
	for _, n := range order {
		if n != name {
			out = append(out, n)
		}
	}
	return out
}

// Account-wide OK state, reused across calls and refreshed on staleness. The
// privileged token + auth_token + anonymLogin session_key are not per-call; only
// vchat is per joinLink.
var (
	okSessionMu     sync.Mutex
	privilegedToken string
	okAuthToken     string
	okSessionKey    string
	okDeviceID      string
)

func randomDeviceID() string {
	var raw [16]byte
	_, _ = rand.Read(raw[:])
	raw[6] = (raw[6] & 0x0f) | 0x40
	raw[8] = (raw[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", raw[0:4], raw[4:6], raw[6:8], raw[8:10], raw[10:16])
}

// turnUsernameLifetime parses the TURN REST username "expiryUnix:userId" and
// returns the remaining lifetime minus a safety margin, defaulting when it cannot
// be parsed.
func turnUsernameLifetime(username string) time.Duration {
	const fallback = 8 * time.Minute
	parts := strings.SplitN(username, ":", 2)
	exp, err := strconv.ParseInt(parts[0], 10, 64)
	if err != nil || exp <= 0 {
		return fallback
	}
	d := time.Until(time.Unix(exp, 0)) - 60*time.Second
	if d < time.Minute {
		return time.Minute
	}
	return d
}

// getAccountVkCreds runs the authorized OK chain for one call join link and
// returns TURN user, credential, addresses and remaining lifetime. It mints +
// caches the privileged token (from session cookies), the OK auth_token and the
// anonymLogin session, re-minting each on staleness, and asks the host app
// (vk_cookies_required) to refresh the session when login.vk.com rejects it.
func getAccountVkCreds(ctx context.Context, link string, resolver *protectedResolver) (string, string, []string, time.Duration, error) {
	cookies, ua, ready := getVkSession()
	if cookies == "" {
		emitProxyEvent(vkAccountAuthEvent{Type: "vk_cookies_required"})
		log.Printf("[VK Auth] waiting for host app to deliver VK session cookies")
		// Suspend the session ready-timeout while we wait for the host app to
		// deliver cookies (this can take minutes); endAccountAuthWait must run on
		// every exit path so the pending counter stays balanced.
		beginAccountAuthWait()
		select {
		case <-ready:
			endAccountAuthWait()
		case <-ctx.Done():
			endAccountAuthWait()
			return "", "", nil, 0, ctx.Err()
		case <-time.After(accountAuthWaitTimeout):
			endAccountAuthWait()
			return "", "", nil, 0, fmt.Errorf("timed out waiting for VK session cookies")
		}
		cookies, ua, _ = getVkSession()
		if cookies == "" {
			return "", "", nil, 0, fmt.Errorf("VK session cookies not available")
		}
	}

	profile := getRandomProfile()
	client, err := resolver.newTLSHTTPClient(profile, 20*time.Second)
	if err != nil {
		return "", "", nil, 0, fmt.Errorf("tls client: %w", err)
	}
	defer client.CloseIdleConnections()

	post := func(rawURL string, form url.Values, extra map[string]string) (map[string]interface{}, error) {
		req, reqErr := newFHTTPRequest(ctx, "POST", rawURL, []byte(form.Encode()))
		if reqErr != nil {
			return nil, reqErr
		}
		parsed, _ := url.Parse(rawURL)
		req.Host = parsed.Hostname()
		applyBrowserProfileFhttp(req, profile)
		req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("Accept", "*/*")
		req.Header.Set("Origin", "https://vk.com")
		req.Header.Set("Referer", "https://vk.com/")
		for k, v := range extra {
			if v != "" {
				req.Header.Set(k, v)
			}
		}
		resp, doErr := client.Do(req)
		if doErr != nil {
			return nil, doErr
		}
		defer func() { _ = resp.Body.Close() }()
		if isVkHost(parsed.Hostname()) {
			mergeVkSetCookies(resp.Cookies())
		}
		body, readErr := io.ReadAll(resp.Body)
		if readErr != nil {
			return nil, readErr
		}
		var out map[string]interface{}
		if jsonErr := json.Unmarshal(body, &out); jsonErr != nil {
			return nil, fmt.Errorf("decode %s: %w", parsed.Host, jsonErr)
		}
		return out, nil
	}

	okSessionMu.Lock()
	defer okSessionMu.Unlock()

	// Step 0: privileged web token via login.vk.com (needs live session cookies).
	if privilegedToken == "" {
		form := url.Values{}
		form.Set("version", "1")
		form.Set("app_id", vkWebTokenAppID)
		resp, mintErr := post(vkWebTokenURL, form, map[string]string{"Cookie": cookies, "User-Agent": ua})
		if mintErr != nil {
			return "", "", nil, 0, fmt.Errorf("web_token mint: %w", mintErr)
		}
		if t, _ := resp["type"].(string); t != "okay" {
			setVkCookies("", "")
			emitProxyEvent(vkAccountAuthEvent{Type: "vk_cookies_required"})
			return "", "", nil, 0, fmt.Errorf("web_token mint rejected session: %v", resp)
		}
		data, _ := resp["data"].(map[string]interface{})
		tok, _ := data["access_token"].(string)
		if tok == "" {
			return "", "", nil, 0, fmt.Errorf("web_token mint: empty token in %v", resp)
		}
		privilegedToken = tok
		okAuthToken = ""
	}

	// Step 1: auth_token via execute{messages.getCallToken}.
	if okAuthToken == "" {
		form := url.Values{}
		form.Set("code", `return API.messages.getCallToken({"env":"production"});`)
		form.Set("access_token", privilegedToken)
		resp, callErr := post(vkExecuteURL, form, nil)
		if callErr != nil {
			return "", "", nil, 0, fmt.Errorf("getCallToken: %w", callErr)
		}
		if apiErr, ok := resp["error"]; ok {
			privilegedToken = ""
			return "", "", nil, 0, fmt.Errorf("getCallToken rejected token: %v", apiErr)
		}
		r, _ := resp["response"].(map[string]interface{})
		tok, _ := r["token"].(string)
		if tok == "" {
			return "", "", nil, 0, fmt.Errorf("getCallToken: empty token in %v", resp)
		}
		okAuthToken = tok
		okSessionKey = ""
	}

	// Step 2: OK session via auth.anonymLogin (account-bound by auth_token).
	if okSessionKey == "" {
		if okDeviceID == "" {
			okDeviceID = randomDeviceID()
		}
		sd, _ := json.Marshal(map[string]interface{}{
			"version":        3,
			"device_id":      okDeviceID,
			"client_version": 1.1,
			"client_type":    "SDK_JS",
			"auth_token":     okAuthToken,
		})
		form := url.Values{}
		form.Set("session_data", string(sd))
		form.Set("method", "auth.anonymLogin")
		form.Set("format", "JSON")
		form.Set("application_key", okCallsAppKey)
		resp, loginErr := post(okCallsFbDo, form, nil)
		if loginErr != nil {
			return "", "", nil, 0, fmt.Errorf("anonymLogin: %w", loginErr)
		}
		sk, _ := resp["session_key"].(string)
		if sk == "" {
			okAuthToken = ""
			return "", "", nil, 0, fmt.Errorf("anonymLogin: no session_key (%v)", resp)
		}
		okSessionKey = sk
	}

	// Step 3: vchat.joinConversationByLink -> turn_server.
	form := url.Values{}
	form.Set("joinLink", link)
	form.Set("isVideo", "false")
	form.Set("protocolVersion", "5")
	form.Set("capabilities", "2F7F")
	form.Set("method", "vchat.joinConversationByLink")
	form.Set("format", "JSON")
	form.Set("application_key", okCallsAppKey)
	form.Set("session_key", okSessionKey)
	resp, joinErr := post(okCallsFbDo, form, nil)
	if joinErr != nil {
		return "", "", nil, 0, fmt.Errorf("vchat join: %w", joinErr)
	}
	ts, ok := resp["turn_server"].(map[string]interface{})
	if !ok {
		okSessionKey = ""
		return "", "", nil, 0, fmt.Errorf("vchat join: no turn_server (%v)", resp)
	}
	username, _ := ts["username"].(string)
	credential, _ := ts["credential"].(string)
	var urls []string
	if arr, ok := ts["urls"].([]interface{}); ok {
		for _, u := range arr {
			if s, ok := u.(string); ok {
				urls = append(urls, s)
			}
		}
	}
	if username == "" || credential == "" || len(urls) == 0 {
		return "", "", nil, 0, fmt.Errorf("vchat join: incomplete turn_server")
	}
	return username, credential, turnURLsToAddresses(urls), turnUsernameLifetime(username), nil
}
