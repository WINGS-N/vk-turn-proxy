package main

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"

	tlsprofiles "github.com/bogdanfinn/tls-client/profiles"
)

func desktopChromeProfile() Profile {
	return Profile{
		Family:          FamilyChrome,
		UserAgent:       "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36",
		SecChUa:         `"Google Chrome";v="146", "Chromium";v="146", "Not.A/Brand";v="24"`,
		SecChUaMobile:   "?0",
		SecChUaPlatform: `"Windows"`,
		AcceptLanguage:  "ru-RU,ru;q=0.9,en-US;q=0.8,en;q=0.7",
		NavPlatform:     "Win32",
		TLS:             tlsprofiles.Chrome_146,
	}
}

func mobileSafariProfile() Profile {
	return Profile{
		Family:         FamilySafari,
		UserAgent:      "Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Mobile/15E148 Safari/604.1",
		AcceptLanguage: "ru-RU,ru;q=0.9,en-US;q=0.8,en;q=0.7",
		NavPlatform:    "iPhone",
	}
}

func TestBuildCaptchaPowTelemetryMatchesProfile(t *testing.T) {
	desktop := buildCaptchaPowTelemetry(desktopChromeProfile(), "vk.com")
	globals, ok := desktop.Globals.Result.(captchaProbeGlobals)
	if !ok {
		t.Fatalf("globals probe carries %T", desktop.Globals.Result)
	}
	if globals.Mem == nil || *globals.Mem != captchaProbeDeviceMemory {
		t.Fatalf("chromium must report device memory, got %v", globals.Mem)
	}
	if globals.PluginsLen != len(captchaChromePlugins) || globals.LanguagesLen != 4 {
		t.Fatalf("globals disagree with the probes: plugins=%d languages=%d", globals.PluginsLen, globals.LanguagesLen)
	}
	ua, ok := desktop.UA.Result.(captchaProbeUA)
	if !ok || ua.UserAgentData == nil {
		t.Fatalf("chromium must carry userAgentData, got %#v", desktop.UA.Result)
	}
	if len(ua.UserAgentData.Brands) != 3 || ua.UserAgentData.Brands[0].Version != "146" {
		t.Fatalf("brands not taken from sec-ch-ua: %#v", ua.UserAgentData.Brands)
	}
	if ua.UserAgentData.Platform != "Windows" || ua.UserAgentData.Mobile {
		t.Fatalf("platform drifted from the profile: %#v", ua.UserAgentData)
	}

	mobile := buildCaptchaPowTelemetry(mobileSafariProfile(), "vk.com")
	mobileUA, ok := mobile.UA.Result.(captchaProbeUA)
	if !ok || mobileUA.UserAgentData != nil {
		t.Fatalf("safari never reports userAgentData: %#v", mobile.UA.Result)
	}
	mobileGlobals, ok := mobile.Globals.Result.(captchaProbeGlobals)
	if !ok || mobileGlobals.Mem != nil || mobileGlobals.PluginsLen != 0 {
		t.Fatalf("safari must report neither memory nor plugins: %#v", mobile.Globals.Result)
	}
	touch, ok := mobile.MaxTouchPoints.Result.(captchaProbeTouch)
	if !ok || touch.MaxTouchPoints == 0 {
		t.Fatalf("a phone reports touch points, got %#v", mobile.MaxTouchPoints.Result)
	}
	media, ok := mobile.MatchMedia.Result.(captchaProbeMatchMedia)
	if !ok || media.PointerFine {
		t.Fatalf("a phone has no fine pointer: %#v", mobile.MatchMedia.Result)
	}
	if media.PrefersDark == media.PrefersLight {
		t.Fatalf("theme probe must pick one side: %#v", media)
	}
}

func TestBuildCaptchaPowEnvelope(t *testing.T) {
	const prefix = "v1."
	telemetry := buildCaptchaPowTelemetry(desktopChromeProfile(), "vk.com")
	value, err := buildCaptchaPowEnvelope(prefix, strings.Repeat("0", 64), 267, telemetry)
	if err != nil {
		t.Fatalf("envelope: %v", err)
	}
	if !strings.HasPrefix(value, prefix) {
		t.Fatalf("envelope lost the page prefix: %q", value)
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(value, prefix))
	if err != nil {
		t.Fatalf("envelope body is not base64: %v", err)
	}
	var decoded struct {
		Hash       string          `json:"hash"`
		Nonce      int             `json:"nonce"`
		DurationMs int64           `json:"duration_ms"`
		Telemetry  json.RawMessage `json:"telemetry"`
		TelHash    string          `json:"tel_hash"`
	}
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatalf("envelope body is not json: %v", err)
	}
	if decoded.Nonce != 267 || decoded.DurationMs != 4 {
		t.Fatalf("nonce %d duration %d do not describe the solve", decoded.Nonce, decoded.DurationMs)
	}
	var probes map[string]any
	if err := json.Unmarshal(decoded.Telemetry, &probes); err != nil {
		t.Fatalf("telemetry is not json: %v", err)
	}
	if len(probes) != 16 {
		t.Fatalf("expected 16 probes, got %d", len(probes))
	}

	var canonical any
	if err := json.Unmarshal(decoded.Telemetry, &canonical); err != nil {
		t.Fatalf("telemetry reparse: %v", err)
	}
	encoded, err := marshalCaptchaJSON(canonical)
	if err != nil {
		t.Fatalf("canonical encode: %v", err)
	}
	sum := sha256.Sum256(encoded)
	if decoded.TelHash != hex.EncodeToString(sum[:]) {
		t.Fatalf("tel_hash does not cover the telemetry it ships with")
	}
}

func TestMarshalCaptchaJSONKeepsHTMLRunes(t *testing.T) {
	encoded, err := marshalCaptchaJSON(map[string]string{"referrer": "https://vk.com/?a=1&b=2"})
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	if !strings.Contains(string(encoded), "&b=2") {
		t.Fatalf("ampersand must survive, got %s", encoded)
	}
}

func TestParseCaptchaV2PagePowEnvelope(t *testing.T) {
	html := `<script>const powInput = "seed";const difficulty = 3;` +
		`window["captchaPowResult"] = "p1." + btoa(JSON.stringify(result));</script>`
	page, err := parseCaptchaV2Page(html)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if !page.PowEnvelope || page.PowEnvelopePrefix != "p1." {
		t.Fatalf("envelope prefix not read: envelope=%t prefix=%q", page.PowEnvelope, page.PowEnvelopePrefix)
	}
	plain, err := parseCaptchaV2Page(`<script>const powInput = "seed";const difficulty = 3;</script>`)
	if err != nil {
		t.Fatalf("parse plain: %v", err)
	}
	if plain.PowEnvelope {
		t.Fatalf("a page without the envelope must keep the bare hash path")
	}
}
