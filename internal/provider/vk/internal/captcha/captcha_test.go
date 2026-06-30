package captcha

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"github.com/samosvalishe/free-turn-proxy/internal/provider/vk/internal/browserprofile"
)

func TestCaptchaInitSettingContentRefPrefersSettingsKey(t *testing.T) {
	setting := captchaInitSetting{
		Type:        "slider",
		Settings:    "legacy-settings",
		SettingsKey: "new-settings-key",
	}

	got := setting.contentRef()
	if got.Source != "settings_key" || got.Value != "new-settings-key" {
		t.Fatalf("contentRef = %+v, want settings_key/new-settings-key", got)
	}
}

func TestCaptchaInitSettingContentRefLegacySettings(t *testing.T) {
	setting := captchaInitSetting{
		Type:     "slider",
		Settings: "legacy-settings",
	}

	got := setting.contentRef()
	if got.Source != "captcha_settings" || got.Value != "legacy-settings" {
		t.Fatalf("contentRef = %+v, want captcha_settings/legacy-settings", got)
	}
}

func TestParseCaptchaPageSettingsKey(t *testing.T) {
	html := `<html><head><script src="https://static.vk.ru/vkid/1.1.1359/not_robot_captcha.js"></script></head><body>
<script>
window.init = {"data":{"show_captcha_type":"slider","captcha_settings":[{"type":"slider","settings_key":"abc123"}]}};
const powInput = "input";
const difficulty = 2;
</script>
</body></html>`

	page, err := parseCaptchaPage(html)
	if err != nil {
		t.Fatal(err)
	}
	if page.Init == nil || len(page.Init.Data.CaptchaSettings) != 1 {
		t.Fatalf("captcha settings missing: %+v", page.Init)
	}
	got := page.Init.Data.CaptchaSettings[0].contentRef()
	if got.Source != "settings_key" || got.Value != "abc123" {
		t.Fatalf("contentRef = %+v, want settings_key/abc123", got)
	}
}

func TestEncodeCaptchaPoW(t *testing.T) {
	got := encodeCaptchaPoW("00abcdef", 147)
	if !strings.HasPrefix(got, "v2.") {
		t.Fatalf("pow = %q, want v2 prefix", got)
	}
	payload, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(got, "v2."))
	if err != nil {
		t.Fatal(err)
	}
	var decoded struct {
		Hash  string `json:"hash"`
		Nonce int    `json:"nonce"`
	}
	if err := json.Unmarshal(payload, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.Hash != "00abcdef" || decoded.Nonce != 147 {
		t.Fatalf("decoded = %+v, want hash/nonce", decoded)
	}
}

func TestCaptchaDomainFromRedirectURI(t *testing.T) {
	tests := []struct {
		name        string
		redirectURI string
		want        string
	}{
		{
			name:        "vk com from query",
			redirectURI: "https://id.vk.ru/not_robot_captcha?domain=vk.com&session_token=x",
			want:        "vk.com",
		},
		{
			name:        "vk ru from query",
			redirectURI: "https://id.vk.ru/not_robot_captcha?domain=vk.ru&session_token=x",
			want:        "vk.ru",
		},
		{
			name:        "fallback without domain",
			redirectURI: "https://id.vk.ru/not_robot_captcha?session_token=x",
			want:        captchaDomain,
		},
		{
			name:        "fallback invalid url",
			redirectURI: "%",
			want:        captchaDomain,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := captchaDomainFromRedirectURI(tt.redirectURI); got != tt.want {
				t.Fatalf("domain = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestCaptchaConnectionFieldsGatedByFamily(t *testing.T) {
	for _, family := range []browserprofile.Kind{browserprofile.Firefox, browserprofile.Safari} {
		if got := captchaConnectionFields(family, true); got != nil {
			t.Fatalf("%s must omit NetworkInformation telemetry, got %v", family, got)
		}
	}
	got := captchaConnectionFields(browserprofile.Chrome, true)
	if len(got) != 2 || got[0][0] != "connectionRtt" || got[1][0] != "connectionDownlink" {
		t.Fatalf("chrome connection fields = %v, want rtt+downlink", got)
	}
	// Реальный браузер шлёт фиксированную выборку, не привязанную к курсору.
	var rtt []int
	if err := json.Unmarshal([]byte(got[0][1]), &rtt); err != nil || len(rtt) != captchaConnectionSamples {
		t.Fatalf("connectionRtt = %s, want %d samples", got[0][1], captchaConnectionSamples)
	}
}

func TestCaptchaMobileAccelerometerIsGravity(t *testing.T) {
	var pts []struct{ X, Y, Z float64 }
	if err := json.Unmarshal([]byte(captchaMobileAccelerometer()), &pts); err != nil {
		t.Fatal(err)
	}
	if len(pts) != 3 {
		t.Fatalf("samples = %d, want 3", len(pts))
	}
	// Магнитуда каждого сэмпла ~ g (покоящийся телефон).
	for _, p := range pts {
		mag := p.X*p.X + p.Y*p.Y + p.Z*p.Z
		if mag < 64 || mag > 144 { // |a| в [8, 12]
			t.Fatalf("accelerometer magnitude^2 = %.1f, not gravity-like", mag)
		}
	}
}

func TestReverseSwapPairs(t *testing.T) {
	got := reverseSwapPairs([]int{1, 2, 3, 4, 5, 6})
	want := []int{5, 6, 3, 4, 1, 2}
	if len(got) != len(want) {
		t.Fatalf("len = %d, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("reverseSwapPairs = %v, want %v", got, want)
		}
	}
}

func TestBuildSliderCursorIsBrowserLike(t *testing.T) {
	cursor := buildSliderCursor(5, 25)
	if got := captchaCursorPointCount(cursor); got < 70 {
		t.Fatalf("cursor point count = %d, want at least 70", got)
	}
}
