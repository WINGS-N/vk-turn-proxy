package browserprofile

import (
	"os"
	"path/filepath"
	"testing"

	fhttp "github.com/bogdanfinn/fhttp"
)

func TestKindFromString(t *testing.T) {
	cases := []struct {
		in   string
		want Kind
	}{
		{"chrome", Chrome},
		{"firefox", Firefox},
		{"safari", Safari},
		{"", Firefox},
		{"unknown", Firefox},
	}
	for _, tc := range cases {
		if got := KindFromString(tc.in); got != tc.want {
			t.Fatalf("KindFromString(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestProfilePathHonorsEnv(t *testing.T) {
	path := filepath.Join(t.TempDir(), "vk_profile_chrome_42.json")
	t.Setenv("VK_PROFILE_PATH", path)

	want := Saved{Profile: ForKind(Chrome), DeviceJSON: "{}", BrowserFp: "abc123"}
	if err := Save(want); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("profile not written to VK_PROFILE_PATH %s: %v", path, err)
	}

	got, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if got.BrowserFp != want.BrowserFp || got.UserAgent != want.UserAgent {
		t.Fatalf("loaded = %+v, want fp=%s ua=%s", got, want.BrowserFp, want.UserAgent)
	}
}

func TestForKindChrome146(t *testing.T) {
	p := ForKind(Chrome)
	if p.UserAgent != "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36" {
		t.Fatalf("unexpected chrome UA: %q", p.UserAgent)
	}
	if p.SecChUa != `"Google Chrome";v="146", "Chromium";v="146", "Not)A;Brand";v="24"` {
		t.Fatalf("unexpected chrome sec-ch-ua: %q", p.SecChUa)
	}
}

func TestApplyFhttpOmitsClientHintsForFirefoxAndSafari(t *testing.T) {
	for _, kind := range []Kind{Firefox, Safari} {
		req, err := fhttp.NewRequest(fhttp.MethodGet, "https://example.com/", nil)
		if err != nil {
			t.Fatal(err)
		}
		ApplyFhttp(req, ForKind(kind))
		if req.Header.Get("sec-ch-ua") != "" {
			t.Fatalf("%s sec-ch-ua = %q, want empty", kind, req.Header.Get("sec-ch-ua"))
		}
		if req.Header.Get("DNT") != "" {
			t.Fatalf("%s DNT = %q, want empty", kind, req.Header.Get("DNT"))
		}
	}
}

func TestFamily(t *testing.T) {
	for _, kind := range []Kind{Chrome, Firefox, Safari} {
		if got := Family(ForKind(kind)); got != kind {
			t.Fatalf("Family(%s profile) = %q, want %q", kind, got, kind)
		}
	}
	if got := Family(Profile{UserAgent: "curl/8.0"}); got != "" {
		t.Fatalf("Family(unknown) = %q, want empty", got)
	}
}

func TestIsMobile(t *testing.T) {
	if IsMobile(ForKind(Chrome)) {
		t.Fatal("desktop chrome detected as mobile")
	}
	if !IsMobile(Profile{UserAgent: "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/149.0.0.0 Mobile Safari/537.36"}) {
		t.Fatal("android chrome was not detected as mobile")
	}
	if !IsMobile(Profile{UserAgent: ForKind(Chrome).UserAgent, SecChUaMobile: "?1"}) {
		t.Fatal("sec-ch-ua-mobile ?1 was not detected as mobile")
	}
}
