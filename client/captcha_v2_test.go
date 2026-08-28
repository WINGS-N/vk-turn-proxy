package main

import "testing"

func TestExtractDebugInfoV2(t *testing.T) {
	const hash = "59f60d917b13be6a22c076adb2c17df37302c5314d8353a27e72f9fbcc9b4838"
	tests := []struct {
		name     string
		body     string
		want     string
		fallback bool
		wantErr  bool
	}{
		{
			name: "primary wrapped pattern",
			body: `x=debug_info:(window.vk.abc)||"` + hash + `";`,
			want: hash, fallback: false,
		},
		{
			name: "primary bare pattern",
			body: `debug_info:"` + hash + `"`,
			want: hash, fallback: false,
		},
		{
			name: "windowed fallback on wrapper drift",
			body: `debug_info=someNewWrapper(),then later "` + hash + `" appears`,
			want: hash, fallback: true,
		},
		{
			name:    "marker missing",
			body:    `no marker at all "` + hash + `"`,
			wantErr: true,
		},
		{
			name:    "marker present but no hash in window",
			body:    `debug_info then nothing hex-shaped for a while ................................................................................................`,
			wantErr: true,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, fb, err := extractDebugInfoV2([]byte(tc.body))
			if tc.wantErr {
				if err == nil {
					t.Fatalf("want error, got value %q", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tc.want || fb != tc.fallback {
				t.Fatalf("got (%q, fallback=%v), want (%q, fallback=%v)", got, fb, tc.want, tc.fallback)
			}
		})
	}
}

func TestExtractCaptchaV2WindowInit(t *testing.T) {
	tests := []struct {
		name    string
		html    string
		want    string
		wantErr bool
	}{
		{
			name: "balanced nested object",
			html: `<script>window.init = {"data":{"show_captcha_type":"slider"}};</script>`,
			want: `{"data":{"show_captcha_type":"slider"}}`,
		},
		{
			name: "brace inside string value",
			html: `<script>window.init = {"data":{"text":"};"},"next":{"x":1}};</script>`,
			want: `{"data":{"text":"};"},"next":{"x":1}}`,
		},
		{
			name: "escaped quote inside string value",
			html: `<script>window.init={"data":{"text":"a\"}"}};</script>`,
			want: `{"data":{"text":"a\"}"}}`,
		},
		{
			name:    "token missing",
			html:    `<script>var other = {};</script>`,
			wantErr: true,
		},
		{
			name:    "unbalanced",
			html:    `<script>window.init = {"data":{"x":1}</script>`,
			wantErr: true,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := extractCaptchaV2WindowInit(tc.html)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("want error, got %q", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tc.want {
				t.Fatalf("got %q, want %q", got, tc.want)
			}
		})
	}
}

func TestParseCaptchaV2Page(t *testing.T) {
	const uuidValue = "8f14e45f-ceea-467a-9d1a-1cb2f4b1b0c1"

	t.Run("plain consts and uuid debug info", func(t *testing.T) {
		html := `<script src="https://id.vk.com/vkid/1.1.1374/not_robot_captcha.js"></script>` +
			`<script>window.init = {"data":{"show_captcha_type":"checkbox"}};` +
			`const powInput = "seed-value";const difficulty = 5;` +
			`debugInfo: "` + uuidValue + `"</script>`
		page, err := parseCaptchaV2Page(html)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if page.PowInput != "seed-value" || page.PowDifficulty != 5 {
			t.Fatalf("got pow %q/%d, want seed-value/5", page.PowInput, page.PowDifficulty)
		}
		if page.DebugInfo != uuidValue {
			t.Fatalf("got debug info %q, want %q", page.DebugInfo, uuidValue)
		}
		if page.ScriptURL != "https://id.vk.com/vkid/1.1.1374/not_robot_captcha.js" {
			t.Fatalf("got script url %q", page.ScriptURL)
		}
		if page.Init == nil || page.Init.Data.ShowCaptchaType != "checkbox" {
			t.Fatalf("init not parsed: %+v", page.Init)
		}
	})

	t.Run("packed bundle fallback", func(t *testing.T) {
		html := `<script src='/vkid/1.1.1400/not_robot_captcha.js'></script>` +
			`<script>t('cGFja2VkLXNlZWQ=',6,'pow_timeout')</script>`
		page, err := parseCaptchaV2Page(html)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if page.PowInput != "cGFja2VkLXNlZWQ=" || page.PowDifficulty != 6 {
			t.Fatalf("got pow %q/%d, want cGFja2VkLXNlZWQ=/6", page.PowInput, page.PowDifficulty)
		}
		if page.ScriptURL != "/vkid/1.1.1400/not_robot_captcha.js" {
			t.Fatalf("got script url %q", page.ScriptURL)
		}
	})

	t.Run("pow from init settings with default difficulty", func(t *testing.T) {
		html := `<script>window.init = {"data":{"show_captcha_type":"slider","captcha_settings":` +
			`[{"type":"pow","settings":"","settings_key":"init-seed"},` +
			`{"type":"slider","settings":"","settings_key":"slider-key"}]}};</script>`
		page, err := parseCaptchaV2Page(html)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if page.PowInput != "init-seed" {
			t.Fatalf("got pow input %q, want init-seed", page.PowInput)
		}
		if page.PowDifficulty != captchaV2DefaultPowDifficulty {
			t.Fatalf("got difficulty %d, want %d", page.PowDifficulty, captchaV2DefaultPowDifficulty)
		}
		showType, sliderSettings := captchaV2InitialState(page.Init)
		if showType != "slider" || sliderSettings != "slider-key" {
			t.Fatalf("got state %q/%q, want slider/slider-key", showType, sliderSettings)
		}
	})

	t.Run("page without init or script does not fail", func(t *testing.T) {
		page, err := parseCaptchaV2Page(`<html><body>nothing useful</body></html>`)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if page.Init != nil || page.ScriptURL != "" || page.PowInput != "" {
			t.Fatalf("unexpected page: %+v", page)
		}
	})
}

func TestResolveCaptchaV2ScriptURL(t *testing.T) {
	const redirect = "https://id.vk.com/captcha?session_token=abc&domain=vk.ru"
	tests := []struct {
		name   string
		script string
		want   string
	}{
		{name: "absolute kept", script: "https://st.vk.com/a.js", want: "https://st.vk.com/a.js"},
		{name: "relative resolved", script: "/vkid/1.1.1374/not_robot_captcha.js", want: "https://id.vk.com/vkid/1.1.1374/not_robot_captcha.js"},
		{name: "empty falls back", script: "", want: captchaV2FallbackScriptURL},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := resolveCaptchaV2ScriptURL(tc.script, redirect); got != tc.want {
				t.Fatalf("got %q, want %q", got, tc.want)
			}
		})
	}
}

func TestCaptchaV2Domain(t *testing.T) {
	if got := captchaV2Domain("https://id.vk.com/captcha?session_token=abc&domain=vk.ru"); got != "vk.ru" {
		t.Fatalf("got %q, want vk.ru", got)
	}
	if got := captchaV2Domain("https://id.vk.com/captcha?session_token=abc"); got != "vk.com" {
		t.Fatalf("got %q, want vk.com", got)
	}
	if got := captchaV2Domain("://broken"); got != "vk.com" {
		t.Fatalf("got %q, want vk.com", got)
	}
}
