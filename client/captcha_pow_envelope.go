package main

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"math"
	"strings"
	"sync"
)

// Конверт PoW: виджету уходит не голый хеш, а base64 объекта с пробами
// окружения. Голый хеш ВК читает как ответ от чего угодно, только не от
// браузера, поэтому пробы обязаны сходиться с UA, языками и device-отпечатком
type captchaPowEnvelope struct {
	Hash       string          `json:"hash"`
	Nonce      int             `json:"nonce"`
	DurationMs int64           `json:"duration_ms"`
	Telemetry  json.RawMessage `json:"telemetry"`
	TelHash    string          `json:"tel_hash"`
}

// Порядок полей = порядок проб на странице, так их пишет JSON.stringify
type captchaPowTelemetry struct {
	Globals          captchaProbe `json:"globals"`
	UA               captchaProbe `json:"ua"`
	Frame            captchaProbe `json:"frame"`
	MatchMedia       captchaProbe `json:"match_media"`
	Plugins          captchaProbe `json:"plugins"`
	NavTamper        captchaProbe `json:"nav_tamper"`
	Referrer         captchaProbe `json:"referrer"`
	DevTools         captchaProbe `json:"devtools"`
	CSS              captchaProbe `json:"css"`
	NativeIntegrity  captchaProbe `json:"native_integrity"`
	CookieTest       captchaProbe `json:"cookie_test"`
	AncestorOrigins  captchaProbe `json:"ancestor_origins"`
	SandboxBehavior  captchaProbe `json:"sandbox_behavior"`
	MaxTouchPoints   captchaProbe `json:"max_touch_points"`
	TimezoneLocale   captchaProbe `json:"timezone_locale"`
	DevicePixelRatio captchaProbe `json:"device_pixel_ratio"`
}

type captchaProbe struct {
	OK     bool `json:"ok"`
	Result any  `json:"result"`
}

func probeOK(result any) captchaProbe {
	return captchaProbe{OK: true, Result: result}
}

type captchaProbeGlobals struct {
	Doc          bool `json:"doc"`
	Win          bool `json:"win"`
	Nav          bool `json:"nav"`
	Webdriver    bool `json:"webdriver"`
	Subtle       bool `json:"subtle"`
	Secure       bool `json:"secure"`
	GCS          bool `json:"gcs"`
	RAF          bool `json:"raf"`
	Wasm         bool `json:"wasm"`
	PluginsLen   int  `json:"plugins_len"`
	LanguagesLen int  `json:"languages_len"`
	HW           int  `json:"hw"`
	Mem          *int `json:"mem"`
}

type captchaProbeUA struct {
	UserAgent     string              `json:"userAgent"`
	UserAgentData *captchaProbeUAData `json:"userAgentData"`
}

type captchaProbeUAData struct {
	Brands   []captchaUABrand `json:"brands"`
	Platform string           `json:"platform"`
	Mobile   bool             `json:"mobile"`
}

type captchaUABrand struct {
	Brand   string `json:"brand"`
	Version string `json:"version"`
}

type captchaProbeFrame struct {
	FrameElement       *string `json:"frameElement"`
	AncestorOriginsLen int     `json:"ancestorOriginsLen"`
	ParentAccessible   bool    `json:"parentAccessible"`
}

type captchaProbeMatchMedia struct {
	PrefersDark   bool `json:"prefersDark"`
	PrefersLight  bool `json:"prefersLight"`
	ReducedMotion bool `json:"reducedMotion"`
	PointerFine   bool `json:"pointerFine"`
}

type captchaProbePlugins struct {
	Length       int        `json:"length"`
	Names        []string   `json:"names"`
	Descriptions []string   `json:"descriptions"`
	MimeTypes    [][]string `json:"mimeTypes"`
	IsChrome     bool       `json:"isChrome"`
}

type captchaProbeNavTamper struct {
	Tampered       bool   `json:"tampered"`
	ElCtor         string `json:"el_ctor"`
	StyleCtor      string `json:"style_ctor"`
	NavCtor        string `json:"nav_ctor"`
	AlertNative    bool   `json:"alert_native"`
	ToStringNative bool   `json:"to_string_native"`
}

type captchaProbeReferrer struct {
	Referrer string `json:"referrer"`
	InIframe bool   `json:"inIframe"`
	Domain   string `json:"domain"`
}

type captchaProbeDevTools struct {
	Open    bool `json:"open"`
	DelayMs int  `json:"delay_ms"`
}

type captchaProbeCSS struct {
	ExpectedMissing int `json:"expectedMissing"`
}

type captchaProbeNativeIntegrity struct {
	ProtoMatch             bool `json:"protoMatch"`
	XHRNative              bool `json:"xhrNative"`
	XHRSendNative          bool `json:"xhrSendNative"`
	AddEventListenerNative bool `json:"addEventListenerNative"`
	AlertNative            bool `json:"alertNative"`
	ToStringNative         bool `json:"toStringNative"`
}

type captchaProbeCookieTest struct {
	Write bool `json:"write"`
}

type captchaProbeAncestorOrigins struct {
	AncestorOrigin *string `json:"ancestorOrigin"`
}

type captchaProbeSandbox struct {
	OriginIsNull   bool `json:"originIsNull"`
	LocalStorage   bool `json:"localStorage"`
	SessionStorage bool `json:"sessionStorage"`
}

type captchaProbeTouch struct {
	MaxTouchPoints int `json:"maxTouchPoints"`
}

type captchaProbeTimezone struct {
	Timezone  string   `json:"timezone"`
	Languages []string `json:"languages"`
}

type captchaProbeDPR struct {
	DPR              float64 `json:"dpr"`
	Orientation      string  `json:"orientation"`
	OrientationAngle int     `json:"orientationAngle"`
}

const (
	// Совпадает с device-отпечатком в buildCaptchaDeviceJSON: разойдутся эти два
	// числа - и мы сами себя спалим на ровном месте
	captchaProbeHardwareConcurrency = 8
	captchaProbeDeviceMemory        = 8
	captchaProbeTimezoneName        = "Europe/Moscow"
)

// PDF-вьювер есть только у десктопного Chromium, и список у всех один
var (
	captchaChromePlugins   = []string{"PDF Viewer", "Chrome PDF Viewer", "Chromium PDF Viewer", "Microsoft Edge PDF Viewer", "WebKit built-in PDF"}
	captchaChromeMimeTypes = []string{"application/pdf", "text/pdf"}
)

// Тема у живого посетителя между попытками не скачет, поэтому бит берётся раз
// на процесс, а не на каждый заход
var (
	captchaPersonaOnce sync.Once
	captchaPersonaDark bool
)

func captchaPersonaPrefersDark() bool {
	captchaPersonaOnce.Do(func() {
		var pick [1]byte
		if _, err := rand.Read(pick[:]); err == nil {
			captchaPersonaDark = pick[0]%2 == 1
		}
	})
	return captchaPersonaDark
}

// buildCaptchaPowTelemetry описывает страницу такой, какой её видел бы браузер
// профиля: страницу мы тянем верхнеуровневой навигацией, значит и фрейм с
// реферером описывают top-level документ - врозь их менять нельзя
func buildCaptchaPowTelemetry(profile Profile, domain string) captchaPowTelemetry {
	mobile := captchaProfileIsMobile(profile)
	chromium := profile.SecChUa != ""
	languages := captchaProfileLanguages(profile)
	plugins := captchaProbePlugins{Names: []string{}, Descriptions: []string{}, MimeTypes: [][]string{}}
	if chromium && !mobile {
		plugins = captchaDesktopChromePlugins()
	}
	var memory *int
	if chromium {
		value := captchaProbeDeviceMemory
		memory = &value
	}
	var uaData *captchaProbeUAData
	if chromium {
		uaData = &captchaProbeUAData{
			Brands:   captchaProfileBrands(profile),
			Platform: captchaProfilePlatformName(profile),
			Mobile:   mobile,
		}
	}
	dark := captchaPersonaPrefersDark()
	touch := 0
	if mobile {
		touch = 5
	}
	orientation := "landscape-primary"
	if mobile {
		orientation = "portrait-primary"
	}
	return captchaPowTelemetry{
		Globals: probeOK(captchaProbeGlobals{
			Doc:          true,
			Win:          true,
			Nav:          true,
			Webdriver:    false,
			Subtle:       true,
			Secure:       true,
			GCS:          true,
			RAF:          true,
			Wasm:         true,
			PluginsLen:   plugins.Length,
			LanguagesLen: len(languages),
			HW:           captchaProbeHardwareConcurrency,
			Mem:          memory,
		}),
		UA:         probeOK(captchaProbeUA{UserAgent: profile.UserAgent, UserAgentData: uaData}),
		Frame:      probeOK(captchaProbeFrame{ParentAccessible: true}),
		MatchMedia: probeOK(captchaProbeMatchMedia{PrefersDark: dark, PrefersLight: !dark, PointerFine: !mobile}),
		Plugins:    probeOK(plugins),
		NavTamper: probeOK(captchaProbeNavTamper{
			ElCtor:         "HTMLDivElement",
			StyleCtor:      "CSSStyleDeclaration",
			NavCtor:        "Navigator",
			AlertNative:    true,
			ToStringNative: true,
		}),
		Referrer: probeOK(captchaProbeReferrer{Referrer: "https://" + domain + "/", Domain: "id.vk.com"}),
		DevTools: probeOK(captchaProbeDevTools{}),
		CSS:      probeOK(captchaProbeCSS{}),
		NativeIntegrity: probeOK(captchaProbeNativeIntegrity{
			ProtoMatch:             true,
			XHRNative:              true,
			XHRSendNative:          true,
			AddEventListenerNative: true,
			AlertNative:            true,
			ToStringNative:         true,
		}),
		CookieTest:       probeOK(captchaProbeCookieTest{Write: true}),
		AncestorOrigins:  probeOK(captchaProbeAncestorOrigins{}),
		SandboxBehavior:  probeOK(captchaProbeSandbox{LocalStorage: true, SessionStorage: true}),
		MaxTouchPoints:   probeOK(captchaProbeTouch{MaxTouchPoints: touch}),
		TimezoneLocale:   probeOK(captchaProbeTimezone{Timezone: captchaProbeTimezoneName, Languages: languages}),
		DevicePixelRatio: probeOK(captchaProbeDPR{DPR: 1, Orientation: orientation}),
	}
}

func captchaDesktopChromePlugins() captchaProbePlugins {
	out := captchaProbePlugins{
		Length:       len(captchaChromePlugins),
		Names:        captchaChromePlugins,
		Descriptions: make([]string, len(captchaChromePlugins)),
		MimeTypes:    make([][]string, len(captchaChromePlugins)),
		IsChrome:     true,
	}
	for i := range captchaChromePlugins {
		out.Descriptions[i] = "Portable Document Format"
		out.MimeTypes[i] = captchaChromeMimeTypes
	}
	return out
}

func captchaProfileIsMobile(profile Profile) bool {
	return profile.SecChUaMobile == "?1" || strings.Contains(profile.UserAgent, "Mobile")
}

// navigator.userAgentData.platform пишется без кавычек, а sec-ch-ua-platform с ними
func captchaProfilePlatformName(profile Profile) string {
	name := strings.Trim(profile.SecChUaPlatform, `"`)
	if name != "" {
		return name
	}
	switch {
	case strings.Contains(profile.UserAgent, "Windows"):
		return "Windows"
	case strings.Contains(profile.UserAgent, "Android"):
		return "Android"
	case strings.Contains(profile.UserAgent, "Mac OS"):
		return "macOS"
	default:
		return "Linux"
	}
}

// Бренды берутся из sec-ch-ua, чтобы заголовок и navigator не разошлись
func captchaProfileBrands(profile Profile) []captchaUABrand {
	out := make([]captchaUABrand, 0, 3)
	for _, part := range strings.Split(profile.SecChUa, ",") {
		name, version, found := strings.Cut(strings.TrimSpace(part), ";v=")
		if !found {
			continue
		}
		out = append(out, captchaUABrand{
			Brand:   strings.Trim(name, `"`),
			Version: strings.Trim(version, `"`),
		})
	}
	return out
}

// navigator.languages без q-весов, порядок из Accept-Language
func captchaProfileLanguages(profile Profile) []string {
	out := make([]string, 0, 4)
	for _, part := range strings.Split(acceptLanguageOf(profile), ",") {
		tag, _, _ := strings.Cut(strings.TrimSpace(part), ";")
		if tag != "" {
			out = append(out, tag)
		}
	}
	return out
}

// Цикл в браузере синхронный, так что время счёта растёт с числом попыток
func captchaPowDurationMs(nonce int) int64 {
	ms := int64(math.Round(float64(nonce+1) * 0.015))
	if ms < 1 {
		return 1
	}
	return ms
}

// buildCaptchaPowEnvelope собирает значение, которое страница отдаёт виджету
func buildCaptchaPowEnvelope(prefix string, hash string, nonce int, telemetry captchaPowTelemetry) (string, error) {
	raw, err := marshalCaptchaJSON(telemetry)
	if err != nil {
		return "", err
	}
	telHash, err := captchaTelemetryHash(raw)
	if err != nil {
		return "", err
	}
	body, err := marshalCaptchaJSON(captchaPowEnvelope{
		Hash:       hash,
		Nonce:      nonce,
		DurationMs: captchaPowDurationMs(nonce),
		Telemetry:  raw,
		TelHash:    telHash,
	})
	if err != nil {
		return "", err
	}
	return prefix + base64.StdEncoding.EncodeToString(body), nil
}

// Хеш считается по канонизированному виду: страница сортирует ключи, и разойтись
// тут значит отдать подпись не от тех данных
func captchaTelemetryHash(telemetry []byte) (string, error) {
	var decoded any
	if err := json.Unmarshal(telemetry, &decoded); err != nil {
		return "", err
	}
	canonical, err := marshalCaptchaJSON(decoded)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(canonical)
	return hex.EncodeToString(sum[:]), nil
}

// JSON.stringify не трогает угловые скобки и амперсанд, а encoding/json по
// умолчанию их экранирует: без этого отличается и байт, и хеш
func marshalCaptchaJSON(value any) ([]byte, error) {
	var buffer bytes.Buffer
	encoder := json.NewEncoder(&buffer)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(value); err != nil {
		return nil, err
	}
	return bytes.TrimRight(buffer.Bytes(), "\n"), nil
}
