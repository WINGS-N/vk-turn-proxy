// Parses user-supplied DNS resolvers from -user-dns and prepends them to
// the built-in lists (defaultDohEndpoints / udpDNSServers). The built-in
// list always remains as a fallback so a typo in user-dns can't take down
// resolution entirely.
//
// Supported formats:
//   https://host[:port]/dns-query   — DoH endpoint
//   udp://ip[:port]                  — plain UDP/53 (port optional, defaults to 53)
//   ip[:port]                        — same as udp://
//
// DoT (tls://) is intentionally rejected for now — there is no DoT path in
// this proxy. We log it so the user gets clear feedback instead of silent
// drop.
//
// Hostnames in DoH URLs are bootstrap-resolved via the system resolver once
// at startup. If the bootstrap fails the entry is dropped — Go's default
// HTTP transport could still reach it through the system resolver, but we
// would lose the protected-socket bootstrap path used everywhere else and
// the entry would behave inconsistently with the built-in DoH endpoints.

package main

import (
	"context"
	"log"
	"net"
	"net/url"
	"strings"
	"time"
)

const userDnsBootstrapTimeout = 4 * time.Second

// applyUserDns parses raw and prepends the resulting endpoints to the
// package-level defaultDohEndpoints / udpDNSServers in priority order.
// raw entries can be separated by commas, semicolons, or newlines.
func applyUserDns(raw string) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return
	}
	entries := splitUserDnsEntries(raw)
	var dohExtra []DohEndpoint
	var udpExtra []string
	for _, entry := range entries {
		doh, udp, ok := parseUserDnsEntry(entry)
		if !ok {
			continue
		}
		if doh != nil {
			dohExtra = append(dohExtra, *doh)
		}
		if udp != "" {
			udpExtra = append(udpExtra, udp)
		}
	}
	if len(dohExtra) > 0 {
		defaultDohEndpoints = append(append([]DohEndpoint{}, dohExtra...), defaultDohEndpoints...)
		log.Printf("[DNS] %d user DoH endpoint(s) prepended", len(dohExtra))
	}
	if len(udpExtra) > 0 {
		udpDNSServers = append(append([]string{}, udpExtra...), udpDNSServers...)
		log.Printf("[DNS] %d user UDP resolver(s) prepended", len(udpExtra))
	}
}

func splitUserDnsEntries(raw string) []string {
	fields := strings.FieldsFunc(raw, func(r rune) bool {
		return r == ',' || r == ';' || r == '\n' || r == '\r'
	})
	out := make([]string, 0, len(fields))
	for _, f := range fields {
		f = strings.TrimSpace(f)
		if f != "" {
			out = append(out, f)
		}
	}
	return out
}

// parseUserDnsEntry decides whether the entry is a DoH URL or a plain UDP
// resolver. Returns one of (doh, udp) populated or both zero on error.
func parseUserDnsEntry(entry string) (*DohEndpoint, string, bool) {
	lower := strings.ToLower(entry)
	switch {
	case strings.HasPrefix(lower, "https://"):
		return parseUserDohEntry(entry)
	case strings.HasPrefix(lower, "udp://"):
		ipPort, ok := normalizeUserUdpEntry(entry[len("udp://"):])
		return nil, ipPort, ok
	case strings.HasPrefix(lower, "tls://"), strings.HasPrefix(lower, "dot://"):
		log.Printf("[DNS] DoT entry %q is not supported; skipping", entry)
		return nil, "", false
	default:
		// Bare ip[:port] — treat as UDP/53.
		ipPort, ok := normalizeUserUdpEntry(entry)
		return nil, ipPort, ok
	}
}

func parseUserDohEntry(entry string) (*DohEndpoint, string, bool) {
	parsed, err := url.Parse(entry)
	if err != nil || parsed.Host == "" {
		log.Printf("[DNS] invalid DoH URL %q: %v", entry, err)
		return nil, "", false
	}
	hostname := parsed.Hostname()
	if hostname == "" {
		log.Printf("[DNS] DoH URL %q has empty host", entry)
		return nil, "", false
	}
	// If the URL host is already a literal IP, use it as its own bootstrap.
	if ip := net.ParseIP(hostname); ip != nil {
		return &DohEndpoint{URL: entry, Hostname: hostname, BootstrapIPs: []string{ip.String()}}, "", true
	}
	bootstrap, err := bootstrapResolveHost(hostname)
	if err != nil || len(bootstrap) == 0 {
		log.Printf("[DNS] failed to bootstrap-resolve %q for %q: %v; dropping", hostname, entry, err)
		return nil, "", false
	}
	return &DohEndpoint{URL: entry, Hostname: hostname, BootstrapIPs: bootstrap}, "", true
}

func normalizeUserUdpEntry(entry string) (string, bool) {
	entry = strings.TrimSpace(entry)
	if entry == "" {
		return "", false
	}
	host := entry
	port := "53"
	if h, p, err := net.SplitHostPort(entry); err == nil {
		host = h
		port = p
	}
	if ip := net.ParseIP(host); ip == nil {
		log.Printf("[DNS] UDP resolver %q is not a literal IP; skipping (only IPs are allowed for the bare/udp:// form)", entry)
		return "", false
	}
	return net.JoinHostPort(host, port), true
}

// bootstrapResolveHost looks up A/AAAA via the system resolver with a tight
// deadline. Used once at startup so user DoH endpoints can be dialled by
// IP via the same protected-socket bootstrap as the built-in ones.
func bootstrapResolveHost(host string) ([]string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), userDnsBootstrapTimeout)
	defer cancel()
	addrs, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(addrs))
	for _, a := range addrs {
		ip := a.IP.String()
		if ip != "" && ip != "<nil>" {
			out = append(out, ip)
		}
	}
	return out, nil
}
