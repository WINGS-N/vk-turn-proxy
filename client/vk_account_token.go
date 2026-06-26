package main

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
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
}

func getVkSession() (string, string, <-chan struct{}) {
	vkSessionMu.RLock()
	defer vkSessionMu.RUnlock()
	return vkCookies, vkUA, vkCookieReadyCh
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
		select {
		case <-ready:
		case <-ctx.Done():
			return "", "", nil, 0, ctx.Err()
		case <-time.After(accountAuthWaitTimeout):
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
