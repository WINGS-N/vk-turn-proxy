package main

import (
	"math/rand"
	"net/http"
)

type Profile struct {
	UserAgent       string
	SecChUa         string
	SecChUaMobile   string
	SecChUaPlatform string
	AcceptLanguage  string
}

// profiles contain paired User-Agent and Client Hints strings to harden bot
// detection. Only Chromium-based engines (Chrome, Edge) emit the sec-ch-ua*
// Client Hints; Safari and Firefox never send them, so those entries leave the
// SecChUa fields empty and applyBrowserProfile omits the headers for them.
// Sending Client Hints alongside a Safari/Firefox User-Agent is an instant
// inconsistency that bot detection flags, so the two must stay paired.
var profile = []Profile{
	// Windows Chrome
	{
		UserAgent:       "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36",
		SecChUa:         `"Google Chrome";v="146", "Chromium";v="146", "Not.A/Brand";v="24"`,
		SecChUaMobile:   "?0",
		SecChUaPlatform: `"Windows"`,
		AcceptLanguage:  "en-US,en;q=0.9",
	},
	{
		UserAgent:       "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/145.0.0.0 Safari/537.36",
		SecChUa:         `"Chromium";v="145", "Google Chrome";v="145", "Not_A Brand";v="99"`,
		SecChUaMobile:   "?0",
		SecChUaPlatform: `"Windows"`,
		AcceptLanguage:  "en-US,en;q=0.9",
	},

	// Windows Edge
	{
		UserAgent:       "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36 Edg/146.0.0.0",
		SecChUa:         `"Microsoft Edge";v="146", "Chromium";v="146", "Not.A/Brand";v="24"`,
		SecChUaMobile:   "?0",
		SecChUaPlatform: `"Windows"`,
		AcceptLanguage:  "en-US,en;q=0.9",
	},

	// Windows Firefox (no Client Hints)
	{
		UserAgent:      "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:145.0) Gecko/20100101 Firefox/145.0",
		AcceptLanguage: "en-US,en;q=0.5",
	},

	// macOS Chrome
	{
		UserAgent:       "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36",
		SecChUa:         `"Google Chrome";v="146", "Chromium";v="146", "Not.A/Brand";v="24"`,
		SecChUaMobile:   "?0",
		SecChUaPlatform: `"macOS"`,
		AcceptLanguage:  "en-US,en;q=0.9",
	},

	// macOS Safari (no Client Hints)
	{
		UserAgent:      "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/26.0 Safari/605.1.15",
		AcceptLanguage: "en-US,en;q=0.9",
	},
	{
		UserAgent:      "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.6 Safari/605.1.15",
		AcceptLanguage: "en-US,en;q=0.9",
	},

	// macOS Firefox (no Client Hints)
	{
		UserAgent:      "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:145.0) Gecko/20100101 Firefox/145.0",
		AcceptLanguage: "en-US,en;q=0.5",
	},

	// Linux Chrome
	{
		UserAgent:       "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36",
		SecChUa:         `"Google Chrome";v="146", "Chromium";v="146", "Not.A/Brand";v="24"`,
		SecChUaMobile:   "?0",
		SecChUaPlatform: `"Linux"`,
		AcceptLanguage:  "en-US,en;q=0.9",
	},

	// Linux Firefox (no Client Hints)
	{
		UserAgent:      "Mozilla/5.0 (X11; Linux x86_64; rv:145.0) Gecko/20100101 Firefox/145.0",
		AcceptLanguage: "en-US,en;q=0.5",
	},

	// iOS Safari (no Client Hints)
	{
		UserAgent:      "Mozilla/5.0 (iPhone; CPU iPhone OS 26_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/26.0 Mobile/15E148 Safari/604.1",
		AcceptLanguage: "en-US,en;q=0.9",
	},

	// Android Chrome
	{
		UserAgent:       "Mozilla/5.0 (Linux; Android 15; Pixel 9) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Mobile Safari/537.36",
		SecChUa:         `"Google Chrome";v="146", "Chromium";v="146", "Not.A/Brand";v="24"`,
		SecChUaMobile:   "?1",
		SecChUaPlatform: `"Android"`,
		AcceptLanguage:  "en-US,en;q=0.9",
	},
}

// getRandomProfile returns a paired User-Agent and Client Hints profile.
func getRandomProfile() Profile {
	return profile[rand.Intn(len(profile))]
}

func applyBrowserProfile(req *http.Request, profile Profile) {
	req.Header.Set("User-Agent", profile.UserAgent)
	// Client Hints are Chromium-only. Safari and Firefox profiles leave SecChUa
	// empty, and must not carry sec-ch-ua* headers or the fingerprint is
	// self-contradictory (a Firefox/Safari UA that advertises Chromium hints).
	if profile.SecChUa != "" {
		req.Header.Set("sec-ch-ua", profile.SecChUa)
		req.Header.Set("sec-ch-ua-mobile", profile.SecChUaMobile)
		req.Header.Set("sec-ch-ua-platform", profile.SecChUaPlatform)
	}
	acceptLanguage := profile.AcceptLanguage
	if acceptLanguage == "" {
		acceptLanguage = "en-US,en;q=0.9"
	}
	req.Header.Set("Accept-Language", acceptLanguage)
}
