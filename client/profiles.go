package main

import (
	"math/rand"
	"net/http"
	"strings"

	"github.com/bogdanfinn/tls-client/profiles"
)

// Browser family identifiers for the user-facing fingerprint selector. "auto"
// (or empty) means pick a random profile across every family.
const (
	FamilyAuto    = "auto"
	FamilyChrome  = "chrome"
	FamilyEdge    = "edge"
	FamilySafari  = "safari"
	FamilyFirefox = "firefox"
)

type Profile struct {
	Family          string
	UserAgent       string
	SecChUa         string
	SecChUaMobile   string
	SecChUaPlatform string
	AcceptLanguage  string
	// NavPlatform is the navigator.platform value paired with the UA, used by the
	// captcha device fingerprint so platform and User-Agent never contradict.
	NavPlatform string
	// TLS is the uTLS ClientHello profile paired with the UA so the JA3/JA4
	// fingerprint matches the advertised browser. A Safari UA over a Chrome
	// ClientHello is an instant tell, so the two are kept together here.
	TLS profiles.ClientProfile
}

// profiles pair a User-Agent, Client Hints and a uTLS ClientHello so the HTTP
// and TLS fingerprints stay self-consistent. Only Chromium engines (Chrome,
// Edge) emit sec-ch-ua* Client Hints; Safari and Firefox never send them, so
// those entries leave the SecChUa fields empty and the apply helpers omit the
// headers for them.
var profile = []Profile{
	// Windows Chrome
	{
		Family:          FamilyChrome,
		UserAgent:       "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36",
		SecChUa:         `"Google Chrome";v="146", "Chromium";v="146", "Not.A/Brand";v="24"`,
		SecChUaMobile:   "?0",
		SecChUaPlatform: `"Windows"`,
		AcceptLanguage:  "en-US,en;q=0.9",
		NavPlatform:     "Win32",
		TLS:             profiles.Chrome_146,
	},
	{
		Family:          FamilyChrome,
		UserAgent:       "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36",
		SecChUa:         `"Chromium";v="144", "Google Chrome";v="144", "Not_A Brand";v="99"`,
		SecChUaMobile:   "?0",
		SecChUaPlatform: `"Windows"`,
		AcceptLanguage:  "en-US,en;q=0.9",
		NavPlatform:     "Win32",
		TLS:             profiles.Chrome_144,
	},
	// macOS Chrome
	{
		Family:          FamilyChrome,
		UserAgent:       "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36",
		SecChUa:         `"Google Chrome";v="146", "Chromium";v="146", "Not.A/Brand";v="24"`,
		SecChUaMobile:   "?0",
		SecChUaPlatform: `"macOS"`,
		AcceptLanguage:  "en-US,en;q=0.9",
		NavPlatform:     "MacIntel",
		TLS:             profiles.Chrome_146,
	},
	// Linux Chrome
	{
		Family:          FamilyChrome,
		UserAgent:       "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36",
		SecChUa:         `"Google Chrome";v="146", "Chromium";v="146", "Not.A/Brand";v="24"`,
		SecChUaMobile:   "?0",
		SecChUaPlatform: `"Linux"`,
		AcceptLanguage:  "en-US,en;q=0.9",
		NavPlatform:     "Linux x86_64",
		TLS:             profiles.Chrome_146,
	},

	// Windows Edge
	{
		Family:          FamilyEdge,
		UserAgent:       "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36 Edg/146.0.0.0",
		SecChUa:         `"Microsoft Edge";v="146", "Chromium";v="146", "Not.A/Brand";v="24"`,
		SecChUaMobile:   "?0",
		SecChUaPlatform: `"Windows"`,
		AcceptLanguage:  "en-US,en;q=0.9",
		NavPlatform:     "Win32",
		TLS:             profiles.Chrome_146,
	},

	// Windows Firefox (no Client Hints)
	{
		Family:         FamilyFirefox,
		UserAgent:      "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:147.0) Gecko/20100101 Firefox/147.0",
		AcceptLanguage: "en-US,en;q=0.5",
		NavPlatform:    "Win32",
		TLS:            profiles.Firefox_147,
	},
	// macOS Firefox (no Client Hints)
	{
		Family:         FamilyFirefox,
		UserAgent:      "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:147.0) Gecko/20100101 Firefox/147.0",
		AcceptLanguage: "en-US,en;q=0.5",
		NavPlatform:    "MacIntel",
		TLS:            profiles.Firefox_147,
	},
	// Linux Firefox (no Client Hints)
	{
		Family:         FamilyFirefox,
		UserAgent:      "Mozilla/5.0 (X11; Linux x86_64; rv:147.0) Gecko/20100101 Firefox/147.0",
		AcceptLanguage: "en-US,en;q=0.5",
		NavPlatform:    "Linux x86_64",
		TLS:            profiles.Firefox_147,
	},

	// macOS Safari (no Client Hints). Safari's ClientHello is stable across major
	// versions, so the current UA pairs with the closest available desktop uTLS
	// profile (Safari_16_0).
	{
		Family:         FamilySafari,
		UserAgent:      "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.6 Safari/605.1.15",
		AcceptLanguage: "en-US,en;q=0.9",
		NavPlatform:    "MacIntel",
		TLS:            profiles.Safari_16_0,
	},
	// iOS Safari (no Client Hints) - exact UA/uTLS pairing.
	{
		Family:         FamilySafari,
		UserAgent:      "Mozilla/5.0 (iPhone; CPU iPhone OS 26_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/26.0 Mobile/15E148 Safari/604.1",
		AcceptLanguage: "en-US,en;q=0.9",
		NavPlatform:    "iPhone",
		TLS:            profiles.Safari_IOS_26_0,
	},
}

// browserFamily is the selected fingerprint family; empty / "auto" means random
// across every profile. Set once at startup from the -browser-fp flag, mirroring
// setDnsMode / setVkAuthMode.
var browserFamily string

func setBrowserFamily(family string) {
	switch strings.ToLower(strings.TrimSpace(family)) {
	case FamilyChrome:
		browserFamily = FamilyChrome
	case FamilyEdge:
		browserFamily = FamilyEdge
	case FamilySafari:
		browserFamily = FamilySafari
	case FamilyFirefox:
		browserFamily = FamilyFirefox
	default:
		browserFamily = FamilyAuto
	}
}

// getRandomProfile returns a random profile within the selected family, or a
// random profile across all families when the selection is auto (the default).
func getRandomProfile() Profile {
	if browserFamily != "" && browserFamily != FamilyAuto {
		matches := make([]Profile, 0, len(profile))
		for _, candidate := range profile {
			if candidate.Family == browserFamily {
				matches = append(matches, candidate)
			}
		}
		if len(matches) > 0 {
			return matches[rand.Intn(len(matches))]
		}
	}
	return profile[rand.Intn(len(profile))]
}

func applyBrowserProfile(req *http.Request, profile Profile) {
	req.Header.Set("User-Agent", profile.UserAgent)
	// Client Hints are Chromium-only. Safari and Firefox profiles leave SecChUa
	// empty and must not carry sec-ch-ua* headers, or the fingerprint is
	// self-contradictory (a Firefox/Safari UA advertising Chromium hints).
	if profile.SecChUa != "" {
		req.Header.Set("sec-ch-ua", profile.SecChUa)
		req.Header.Set("sec-ch-ua-mobile", profile.SecChUaMobile)
		req.Header.Set("sec-ch-ua-platform", profile.SecChUaPlatform)
	}
	req.Header.Set("Accept-Language", acceptLanguageOf(profile))
}

func acceptLanguageOf(profile Profile) string {
	if profile.AcceptLanguage != "" {
		return profile.AcceptLanguage
	}
	return "en-US,en;q=0.9"
}
