package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	mathrand "math/rand"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	fhttp "github.com/bogdanfinn/fhttp"
	tlsclient "github.com/bogdanfinn/tls-client"
)

const (
	captchaV2APIVersion    = "5.131"
	captchaV2ScriptVersion = "1.1.1374"
	captchaV2DeviceInfo    = `{"screenWidth":1920,"screenHeight":1080,"screenAvailWidth":1920,"screenAvailHeight":1080,"innerWidth":1920,"innerHeight":951,"devicePixelRatio":1,"language":"en-US","languages":["en-US","en"],"webdriver":false,"hardwareConcurrency":8,"notificationsPermission":"denied"}`
)

var (
	reCaptchaV2PowInput   = regexp.MustCompile(`const\s+powInput\s*=\s*"([^"]+)"`)
	reCaptchaV2Difficulty = regexp.MustCompile(`const\s+difficulty\s*=\s*(\d+)`)
	reCaptchaV2WindowInit = regexp.MustCompile(`(?s)window\.init\s*=\s*(\{.*?})\s*;`)
	reCaptchaV2ScriptSrc  = regexp.MustCompile(`src="(https://[^"]+not_robot_captcha[^"]+)"`)
	reCaptchaV2DebugInfo  = regexp.MustCompile(`debug_info:(?:[^"]*\|\|)?"([a-fA-F0-9]{64})"`)
	reCaptchaV2Hex64      = regexp.MustCompile(`"([a-fA-F0-9]{64})"`)
	reCaptchaV2Version    = regexp.MustCompile(`vkid/([0-9.]*)/not_robot_captcha\.js`)

	errCaptchaV2RateLimit = errors.New("captcha session rate limit reached")
	// VK now serves a bot verdict on the checkbox flow instead of a solvable
	// challenge; treat it distinctly so the solver falls back to the slider rather
	// than giving up as if rate limited. Ported from amurcanov/proxy-turn-vk-android.
	errCaptchaV2Bot = errors.New("captcha bot challenge")

	// Attempt budget for a single automatic v2 solve before the caller falls back
	// to the v1 solver.
	captchaV2MaxAttempts = 10

	captchaV2DebugCache  sync.Map // scriptURL -> string
	captchaV2VersionSeen sync.Map // script version -> struct{} (drift warned once)
	captchaV2HeaderOrder = []string{
		"host",
		"content-length",
		"sec-ch-ua-platform",
		"accept-language",
		"sec-ch-ua",
		"content-type",
		"sec-ch-ua-mobile",
		"user-agent",
		"accept",
		"origin",
		"sec-fetch-site",
		"sec-fetch-mode",
		"sec-fetch-dest",
		"referer",
		"accept-encoding",
		"priority",
	}
	captchaV2PHeaderOrder = []string{":method", ":path", ":authority", ":scheme"}
)

type captchaV2Init struct {
	Data captchaV2InitData `json:"data"`
}

type captchaV2InitData struct {
	ShowCaptchaType string                 `json:"show_captcha_type"`
	CaptchaSettings []captchaV2InitSetting `json:"captcha_settings"`
}

type captchaV2InitSetting struct {
	Type     string `json:"type"`
	Settings string `json:"settings"`
}

type captchaV2Page struct {
	PowInput      string
	PowDifficulty int
	ScriptURL     string
	Init          *captchaV2Init
}

type captchaV2Check struct {
	Status       string
	SuccessToken string
	ShowType     string
}

type captchaV2ShowTypeError struct {
	ShowType string
}

func (e *captchaV2ShowTypeError) Error() string {
	return "captcha show type mismatch: " + e.ShowType
}

type captchaV2Session struct {
	ctx     context.Context
	client  tlsclient.HttpClient
	profile Profile
}

func dispatchAutoVkCaptcha(
	ctx context.Context,
	captchaErr *vkCaptchaError,
	resolver *protectedResolver,
	profile Profile,
) (string, error) {
	// Surface auto-captcha solving to the app so it shows the same "(captcha)"
	// connect stage as the interactive flow. The stage is cleared by auth_ready
	// (or the next state change) once solving finishes.
	emitCaptchaStateEvent("solving")
	if strings.EqualFold(captchaSolverVersion, "v1") {
		log.Printf("Using captcha solver v1 (legacy)")
		return solveVkCaptcha(ctx, captchaErr, resolver, profile)
	}
	log.Printf("Using captcha solver v2 (improved)")
	token, err := solveVkCaptchaV2(ctx, captchaErr, resolver, profile)
	if err != nil {
		log.Printf("v2 captcha solver failed, falling back to v1: %v", err)
		return solveVkCaptcha(ctx, captchaErr, resolver, profile)
	}
	return token, nil
}

func solveVkCaptchaV2(
	ctx context.Context,
	captchaErr *vkCaptchaError,
	resolver *protectedResolver,
	profile Profile,
) (string, error) {
	if captchaErr == nil || captchaErr.SessionToken == "" {
		return "", fmt.Errorf("no session_token in redirect_uri")
	}
	log.Printf("Solving VK Smart Captcha automatically (v2)...")

	client, err := resolver.newTLSHTTPClient(profile, 20*time.Second)
	if err != nil {
		return "", fmt.Errorf("failed to initialize tls client: %w", err)
	}
	defer client.CloseIdleConnections()

	s := &captchaV2Session{ctx: ctx, client: client, profile: profile}

	for attempt := 1; attempt <= captchaV2MaxAttempts; attempt++ {
		token, solveErr := s.solveOnce(captchaErr)
		if solveErr == nil {
			return token, nil
		}
		log.Printf("v2 captcha solve attempt %d/%d failed: %v", attempt, captchaV2MaxAttempts, solveErr)

		// A session rate limit used to abort the whole solve; wait it out and retry
		// within the attempt budget instead, so a transient limit does not fail the
		// connect. Ported from amurcanov/proxy-turn-vk-android.
		var delay time.Duration
		if errors.Is(solveErr, errCaptchaV2RateLimit) {
			delay = 5 * time.Second
		} else {
			backoffSteps := attempt
			if backoffSteps > 10 {
				backoffSteps = 10
			}
			delay = time.Duration(backoffSteps)*500*time.Millisecond +
				time.Duration(mathrand.Intn(1200))*time.Millisecond
		}
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return "", ctx.Err()
		case <-timer.C:
		}
	}
	return "", fmt.Errorf("v2 captcha attempts exhausted (%d)", captchaV2MaxAttempts)
}

func (s *captchaV2Session) solveOnce(captchaErr *vkCaptchaError) (string, error) {
	html, err := s.fetchCaptchaHTML(captchaErr.RedirectURI)
	if err != nil {
		return "", err
	}

	page, err := parseCaptchaV2Page(html)
	if err != nil {
		return "", err
	}
	if page.PowInput == "" {
		return "", errors.New("failed to find PoW settings")
	}

	sliderSettings := ""
	if page.Init != nil {
		for _, setting := range page.Init.Data.CaptchaSettings {
			if setting.Type == "slider" {
				sliderSettings = setting.Settings
			}
		}
	}
	if page.Init != nil && page.Init.Data.ShowCaptchaType == "slider" && sliderSettings == "" {
		return "", errors.New("failed to find slider captcha settings")
	}

	log.Printf("v2 captcha solving pow difficulty=%d", page.PowDifficulty)
	hash := solveCaptchaPoWV2(s.ctx, page.PowInput, page.PowDifficulty)
	if hash == "" {
		return "", errors.New("captcha pow failed")
	}
	log.Printf("v2 captcha pow solved")

	base := captchaV2BaseValues(captchaErr.SessionToken)
	if _, err := s.captchaRequest("captchaNotRobot.settings", base); err != nil {
		return "", fmt.Errorf("captcha settings failed: %w", err)
	}

	browserFP, err := captchaV2BrowserFP()
	if err != nil {
		return "", err
	}

	s.warnVersionDrift(page.ScriptURL)

	debugInfo, err := s.fetchDebugInfo(page.ScriptURL)
	if err != nil {
		return "", fmt.Errorf("failed to fetch debug info: %w (script_version=%s)", err, captchaV2ScriptVersion)
	}

	showType := ""
	if page.Init != nil {
		showType = page.Init.Data.ShowCaptchaType
	}
	var token string
	for {
		log.Printf("v2 captcha solving show_type=%s", showType)
		switch showType {
		case "slider":
			token, err = s.solveSliderCaptcha(captchaErr.SessionToken, browserFP, hash, sliderSettings, debugInfo)
		case "checkbox", "":
			token, err = s.solveCheckboxCaptcha(captchaErr.SessionToken, browserFP, hash, debugInfo)
		default:
			return "", fmt.Errorf("unsupported captcha type: %s", showType)
		}
		if err == nil {
			break
		}
		// VK increasingly answers the checkbox flow with a bot verdict while the
		// slider flow still clears, so switch to the slider once before giving up.
		// Ported from amurcanov/proxy-turn-vk-android.
		if errors.Is(err, errCaptchaV2Bot) && !strings.EqualFold(showType, "slider") && sliderSettings != "" {
			log.Printf("v2 captcha checkbox returned BOT, retrying with slider")
			showType = "slider"
			continue
		}
		var stErr *captchaV2ShowTypeError
		if !errors.As(err, &stErr) || stErr.ShowType == "" {
			return "", err
		}
		showType = stErr.ShowType
	}

	_, _ = s.captchaRequest("captchaNotRobot.endSession", base)
	return token, nil
}

func captchaV2BaseValues(sessionToken string) [][2]string {
	return [][2]string{
		{"session_token", sessionToken},
		{"domain", "vk.com"},
		{"adFp", ""},
		{"access_token", ""},
	}
}

func captchaV2BrowserFP() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("browser fp generate: %w", err)
	}
	return hex.EncodeToString(b), nil
}

func (s *captchaV2Session) fetchCaptchaHTML(redirectURI string) (string, error) {
	body, err := s.doRaw(fhttp.MethodGet, redirectURI, nil, map[string]string{
		"Accept":         "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
		"Sec-Fetch-Dest": "document",
		"Sec-Fetch-Mode": "navigate",
		"Sec-Fetch-Site": "cross-site",
	})
	if err != nil {
		return "", err
	}
	return string(body), nil
}

func (s *captchaV2Session) fetchDebugInfo(scriptURL string) (string, error) {
	if cached, ok := captchaV2DebugCache.Load(scriptURL); ok {
		return cached.(string), nil
	}
	body, err := s.doRaw(fhttp.MethodGet, scriptURL, nil, map[string]string{
		"Accept":  "text/javascript,*/*",
		"Referer": "https://id.vk.com/",
	})
	if err != nil {
		return "", err
	}
	v, usedFallback, err := extractDebugInfoV2(body)
	if err != nil {
		return "", err
	}
	if usedFallback {
		log.Printf("v2 captcha debug_info primary pattern missed; used windowed fallback (script format drift)")
	}
	captchaV2DebugCache.Store(scriptURL, v)
	log.Printf("v2 captcha debug_info fetched url=%s", scriptURL)
	return v, nil
}

// warnVersionDrift warns once per script version when VK serves a not_robot_captcha
// script newer than the tested baseline: the wire format may have changed, so the
// PoW/answer encoding should be re-checked against live if BOT rejections rise.
func (s *captchaV2Session) warnVersionDrift(scriptURL string) {
	m := reCaptchaV2Version.FindStringSubmatch(scriptURL)
	if len(m) < 2 || m[1] == "" || m[1] == captchaV2ScriptVersion {
		return
	}
	if _, seen := captchaV2VersionSeen.LoadOrStore(m[1], struct{}{}); seen {
		return
	}
	log.Printf("v2 captcha script version %s differs from tested %s; wire unverified - re-check if BOT rejections rise", m[1], captchaV2ScriptVersion)
}

// extractDebugInfoV2 pulls the debug_info 64-hex constant out of the captcha
// script body. VK's format is `debug_info:(...window.vk.X)||"<64hex>"` where the
// window.vk.X wrapper name drifts between builds, so the primary pattern matches
// only the hash literal. When it misses (wrapper changed), fall back to the first
// 64-hex literal in a window right after the debug_info marker. usedFallback flags
// that the wrapper drifted so the caller can log it.
func extractDebugInfoV2(body []byte) (value string, usedFallback bool, err error) {
	if m := reCaptchaV2DebugInfo.FindSubmatch(body); len(m) >= 2 {
		return string(m[1]), false, nil
	}
	idx := bytes.Index(body, []byte("debug_info"))
	if idx < 0 {
		return "", false, errors.New("debug_info marker not found in script")
	}
	end := idx + 256
	if end > len(body) {
		end = len(body)
	}
	if m := reCaptchaV2Hex64.FindSubmatch(body[idx:end]); len(m) >= 2 {
		return string(m[1]), true, nil
	}
	return "", false, fmt.Errorf("debug_info match not found near: %q", body[idx:end])
}

func parseCaptchaV2Page(html string) (*captchaV2Page, error) {
	page := &captchaV2Page{}

	match := reCaptchaV2WindowInit.FindStringSubmatch(html)
	if len(match) < 2 {
		return nil, errors.New("captcha init json not found")
	}
	var init captchaV2Init
	if err := json.Unmarshal([]byte(match[1]), &init); err != nil {
		return nil, fmt.Errorf("captcha init json parse: %w", err)
	}
	page.Init = &init

	match = reCaptchaV2ScriptSrc.FindStringSubmatch(html)
	if len(match) < 2 {
		return nil, errors.New("captcha script url not found")
	}
	page.ScriptURL = match[1]

	if m := reCaptchaV2PowInput.FindStringSubmatch(html); len(m) >= 2 {
		page.PowInput = m[1]
	}
	if page.PowInput == "" {
		return page, nil
	}

	match = reCaptchaV2Difficulty.FindStringSubmatch(html)
	if len(match) < 2 {
		return nil, errors.New("captcha difficulty const not found")
	}
	difficulty, err := strconv.Atoi(match[1])
	if err != nil || difficulty <= 0 {
		return nil, fmt.Errorf("invalid captcha difficulty %q", match[1])
	}
	page.PowDifficulty = difficulty
	return page, nil
}

func (s *captchaV2Session) captchaRequest(method string, form [][2]string) (map[string]any, error) {
	endpoint := "https://api.vk.ru/method/" + method + "?v=" + captchaV2APIVersion
	body, err := s.doRaw(fhttp.MethodPost, endpoint, form, map[string]string{
		"Origin":   "https://id.vk.com",
		"Referer":  "https://id.vk.com/",
		"Priority": "u=1, i",
	})
	if err != nil {
		return nil, err
	}
	var out map[string]any
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, fmt.Errorf("captcha api decode: %w", err)
	}
	return out, nil
}

func (s *captchaV2Session) performCaptchaCheck(
	sessionToken string,
	browserFP string,
	hash string,
	answerJSON string,
	cursor string,
	debugInfo string,
) (*captchaV2Check, error) {
	values := [][2]string{
		{"session_token", sessionToken},
		{"domain", "vk.com"},
		{"adFp", ""},
		{"accelerometer", "[]"},
		{"gyroscope", "[]"},
		{"motion", "[]"},
		{"cursor", cursor},
		{"taps", "[]"},
		{"connectionRtt", "[]"},
		{"connectionDownlink", "[]"},
		{"browser_fp", browserFP},
		{"hash", hash},
		{"answer", base64.StdEncoding.EncodeToString([]byte(answerJSON))},
		{"debug_info", debugInfo},
		{"access_token", ""},
	}
	resp, err := s.captchaRequest("captchaNotRobot.check", values)
	if err != nil {
		return nil, fmt.Errorf("captcha check failed: %w", err)
	}
	check, err := parseCaptchaV2Check(resp)
	if err != nil {
		return nil, err
	}
	log.Printf("v2 captcha check status=%s", check.Status)
	return check, nil
}

func parseCaptchaV2Check(raw map[string]any) (*captchaV2Check, error) {
	resp, ok := raw["response"].(map[string]any)
	if !ok {
		return nil, fmt.Errorf("invalid captcha check response: %v", raw)
	}
	out := &captchaV2Check{
		Status:       captchaV2StringifyAny(resp["status"]),
		SuccessToken: captchaV2StringifyAny(resp["success_token"]),
		ShowType:     captchaV2StringifyAny(resp["show_captcha_type"]),
	}
	if out.Status == "" {
		return nil, fmt.Errorf("captcha check status missing: %v", raw)
	}
	return out, nil
}

func (s *captchaV2Session) solveCheckboxCaptcha(
	sessionToken string,
	browserFP string,
	hash string,
	debugInfo string,
) (string, error) {
	if _, err := s.captchaRequest("captchaNotRobot.componentDone", [][2]string{
		{"session_token", sessionToken},
		{"domain", "vk.com"},
		{"adFp", ""},
		{"browser_fp", browserFP},
		{"device", captchaV2DeviceInfo},
		{"access_token", ""},
	}); err != nil {
		return "", fmt.Errorf("captcha componentDone failed: %w", err)
	}

	select {
	case <-s.ctx.Done():
		return "", s.ctx.Err()
	case <-time.After(time.Duration(400+mathrand.Intn(250)) * time.Millisecond):
	}

	check, err := s.performCaptchaCheck(sessionToken, browserFP, hash, "{}", "[]", debugInfo)
	if err != nil {
		return "", err
	}
	if check.ShowType != "" && !strings.EqualFold(check.ShowType, "checkbox") {
		return "", &captchaV2ShowTypeError{ShowType: check.ShowType}
	}
	if strings.EqualFold(check.Status, "error_limit") {
		return "", errCaptchaV2RateLimit
	}
	if strings.EqualFold(check.Status, "bot") {
		return "", fmt.Errorf("%w: checkbox captcha rejected: status=%s", errCaptchaV2Bot, check.Status)
	}
	if !strings.EqualFold(check.Status, "ok") {
		return "", fmt.Errorf("checkbox captcha rejected: status=%s", check.Status)
	}
	if check.SuccessToken == "" {
		return "", errors.New("captcha success token not found")
	}
	return check.SuccessToken, nil
}

func solveCaptchaPoWV2(ctx context.Context, input string, difficulty int) string {
	if input == "" || difficulty <= 0 {
		return ""
	}
	target := strings.Repeat("0", difficulty)
	for nonce := 1; nonce <= 10_000_000; nonce++ {
		if nonce%4096 == 0 {
			select {
			case <-ctx.Done():
				return ""
			default:
			}
		}
		sum := sha256.Sum256([]byte(input + strconv.Itoa(nonce)))
		hashHex := hex.EncodeToString(sum[:])
		if strings.HasPrefix(hashHex, target) {
			return hashHex
		}
	}
	return ""
}

func (s *captchaV2Session) doRaw(
	method string,
	endpoint string,
	form [][2]string,
	extraHeaders map[string]string,
) ([]byte, error) {
	var body []byte
	if form != nil {
		body = []byte(captchaV2EncodeForm(form))
	}
	req, err := newFHTTPRequest(s.ctx, method, endpoint, body)
	if err != nil {
		return nil, err
	}
	applyBrowserProfileFhttp(req, s.profile)
	req.Header.Set("Accept", "*/*")
	req.Header.Set("Sec-Fetch-Site", "same-site")
	req.Header.Set("Sec-Fetch-Mode", "cors")
	req.Header.Set("Sec-Fetch-Dest", "empty")
	req.Header.Set("Origin", "https://vk.com")
	req.Header.Set("Referer", "https://vk.com/")
	if form != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	for k, v := range extraHeaders {
		req.Header.Set(k, v)
	}
	req.Header[fhttp.HeaderOrderKey] = captchaV2HeaderOrder
	req.Header[fhttp.PHeaderOrderKey] = captchaV2PHeaderOrder

	resp, err := s.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() {
		if closeErr := resp.Body.Close(); closeErr != nil {
			log.Printf("v2 captcha close body: %s", closeErr)
		}
	}()
	return io.ReadAll(resp.Body)
}

func captchaV2EncodeForm(values [][2]string) string {
	if len(values) == 0 {
		return ""
	}
	var sb strings.Builder
	for i, kv := range values {
		if i > 0 {
			sb.WriteByte('&')
		}
		sb.WriteString(captchaV2QueryEscape(kv[0]))
		sb.WriteByte('=')
		sb.WriteString(captchaV2QueryEscape(kv[1]))
	}
	return sb.String()
}

func captchaV2QueryEscape(s string) string {
	const upper = "0123456789ABCDEF"
	hexDigits := func(b byte) [3]byte {
		return [3]byte{'%', upper[b>>4], upper[b&0xF]}
	}
	out := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == ' ':
			out = append(out, '+')
		case ('a' <= c && c <= 'z') || ('A' <= c && c <= 'Z') || ('0' <= c && c <= '9') || c == '-' || c == '_' || c == '.' || c == '~':
			out = append(out, c)
		default:
			h := hexDigits(c)
			out = append(out, h[:]...)
		}
	}
	return string(out)
}

func captchaV2StringifyAny(value any) string {
	switch v := value.(type) {
	case nil:
		return ""
	case string:
		return v
	case float64:
		return strconv.FormatFloat(v, 'f', -1, 64)
	case bool:
		return strconv.FormatBool(v)
	default:
		data, err := json.Marshal(v)
		if err != nil {
			return fmt.Sprintf("%v", v)
		}
		return string(data)
	}
}
