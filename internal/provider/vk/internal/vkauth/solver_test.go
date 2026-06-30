package vkauth

import (
	"testing"

	"github.com/samosvalishe/free-turn-proxy/internal/provider/vk/internal/browserprofile"
)

func TestCaptchaSolveModeForAttempt(t *testing.T) {
	t.Parallel()

	t.Run("default flow", func(t *testing.T) {
		t.Parallel()

		mode, ok := CaptchaSolveModeForAttempt(0, false)
		if !ok || mode != CaptchaSolveModeAuto {
			t.Fatalf("expected first attempt to use auto captcha, got mode=%v ok=%v", mode, ok)
		}

		mode, ok = CaptchaSolveModeForAttempt(1, false)
		if !ok || mode != CaptchaSolveModeManual {
			t.Fatalf("expected second attempt to use manual captcha, got mode=%v ok=%v", mode, ok)
		}

		if _, ok = CaptchaSolveModeForAttempt(2, false); ok {
			t.Fatal("expected only two attempts in default flow")
		}
	})

	t.Run("manual only flow", func(t *testing.T) {
		t.Parallel()

		mode, ok := CaptchaSolveModeForAttempt(0, true)
		if !ok || mode != CaptchaSolveModeManual {
			t.Fatalf("expected manual mode on first attempt, got mode=%v ok=%v", mode, ok)
		}

		if _, ok = CaptchaSolveModeForAttempt(1, true); ok {
			t.Fatal("expected only one manual captcha attempt when manual mode is forced")
		}
	})
}

func TestSavedProfileUsable(t *testing.T) {
	t.Parallel()

	if savedProfileUsable(browserprofile.Saved{}) {
		t.Fatal("empty profile must be unusable (no UA to impersonate)")
	}
	if savedProfileUsable(browserprofile.Saved{Profile: browserprofile.Profile{UserAgent: "   "}}) {
		t.Fatal("whitespace UA must be unusable")
	}
	mobile := browserprofile.Saved{Profile: browserprofile.Profile{
		UserAgent:     "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Mobile Safari/537.36",
		SecChUaMobile: "?1",
	}}
	if !savedProfileUsable(mobile) {
		t.Fatal("captured mobile profile must be usable")
	}
}

func TestNormalizeFamily(t *testing.T) {
	t.Parallel()

	cases := map[browserprofile.Kind]browserprofile.Kind{
		browserprofile.Firefox: browserprofile.Firefox,
		browserprofile.Safari:  browserprofile.Safari,
		browserprofile.Chrome:  browserprofile.Chrome,
		"":                     browserprofile.Chrome,
		"weird":                browserprofile.Chrome,
	}
	for in, want := range cases {
		if got := normalizeFamily(in); got != want {
			t.Fatalf("normalizeFamily(%q) = %q, want %q", in, got, want)
		}
	}
}
