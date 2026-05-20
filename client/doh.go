// DNS-over-HTTPS resolver for mobile networks where UDP/53 is blocked or
// spoofed.

package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"sort"
	"sync"
	"time"

	"github.com/miekg/dns"

	// Embedded Mozilla CA roots for CGO_ENABLED=0 builds (Android).
	_ "golang.org/x/crypto/x509roots/fallback"
)

const (
	dohQueryTimeout     = 6 * time.Second
	dohCacheMinTTL      = 10 * time.Second
	dohCacheMaxTTL      = 1 * time.Hour
	dohMaxResponseBytes = 64 * 1024
	dohContentType      = "application/dns-message"

	dohDialerTimeout   = 5 * time.Second
	dohDialerKeepAlive = 30 * time.Second
	appDialerTimeout   = 20 * time.Second
	appDialerKeepAlive = 30 * time.Second
)

const (
	DNSModeUDP  = "udp"
	DNSModeDoH  = "doh"
	DNSModeAuto = "auto"
)

// udpDNSServers is the fallback list of plain UDP/53 resolvers used by
// the user-supplied DNS bridge (see user_dns.go) when no -user-dns
// entries respond.
var udpDNSServers = []string{
	"77.88.8.8:53", "77.88.8.1:53",
	"8.8.8.8:53", "8.8.4.4:53",
	"1.1.1.1:53", "1.0.0.1:53",
}

// DohEndpoint describes a single DNS-over-HTTPS server together with the IPs
// we bootstrap to — so that resolving the endpoint hostname does not itself
// require DNS.
type DohEndpoint struct {
	URL          string
	Hostname     string
	BootstrapIPs []string
}

// Yandex is tried first because it tends to stay reachable on RU mobile
// operators even when international resolvers get blocked; Google and
// Cloudflare follow as fallbacks.
var defaultDohEndpoints = []DohEndpoint{
	{"https://common.dot.dns.yandex.net/dns-query", "common.dot.dns.yandex.net", []string{"77.88.8.8", "77.88.8.1"}},
	{"https://secure.dot.dns.yandex.net/dns-query", "secure.dot.dns.yandex.net", []string{"77.88.8.88", "77.88.8.2"}},
	{"https://family.dot.dns.yandex.net/dns-query", "family.dot.dns.yandex.net", []string{"77.88.8.7", "77.88.8.3"}},
	{"https://dns.google/dns-query", "dns.google", []string{"8.8.8.8", "8.8.4.4"}},
	{"https://cloudflare-dns.com/dns-query", "cloudflare-dns.com", []string{"1.1.1.1", "1.0.0.1"}},
}

// DohResolver resolves hostnames to IPs via DNS-over-HTTPS (RFC 8484).
type DohResolver struct {
	endpoints []DohEndpoint
	client    *http.Client
	cache     *dohCache
}

// NewDohResolver constructs a resolver using defaultDohEndpoints if endpoints
// is nil. Endpoint hostnames are dialed by IP using BootstrapIPs, so the DoH
// transport never depends on the system resolver.
//
// bridge is optional; when supplied, the bootstrap dialer marks its sockets
// via VpnService.protect() so DoH HTTPS to public IPs doesn't loop through
// our own VPN tunnel.
func NewDohResolver(endpoints []DohEndpoint, bridge *protectBridge) *DohResolver {
	if len(endpoints) == 0 {
		endpoints = defaultDohEndpoints
	}
	return &DohResolver{
		endpoints: endpoints,
		client:    &http.Client{Timeout: dohQueryTimeout, Transport: newBootstrapTransport(endpoints, bridge)},
		cache:     newDohCache(),
	}
}

// newBootstrapTransport returns an http.Transport whose DialContext only
// knows how to reach the configured DoH endpoint hostnames, by mapping each
// to its BootstrapIPs.
func newBootstrapTransport(endpoints []DohEndpoint, bridge *protectBridge) *http.Transport {
	bootstrap := make(map[string][]string, len(endpoints))
	for _, ep := range endpoints {
		bootstrap[ep.Hostname] = ep.BootstrapIPs
	}
	dialer := &net.Dialer{Timeout: dohDialerTimeout, KeepAlive: dohDialerKeepAlive}
	if bridge != nil {
		dialer.Control = bridge.Control
	}

	return &http.Transport{
		MaxIdleConns:        8,
		MaxIdleConnsPerHost: 2,
		IdleConnTimeout:     90 * time.Second,
		ForceAttemptHTTP2:   true,
		TLSClientConfig:     &tls.Config{MinVersion: tls.VersionTLS12},
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			host, port, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, err
			}
			ips, ok := bootstrap[host]
			if !ok {
				return nil, fmt.Errorf("doh: no bootstrap IPs for %q", host)
			}
			var lastErr error
			for _, ip := range ips {
				conn, derr := dialer.DialContext(ctx, network, net.JoinHostPort(ip, port))
				if derr == nil {
					return conn, nil
				}
				lastErr = derr
			}
			return nil, lastErr
		},
	}
}

// LookupIPAddr resolves host to a combined list of A+AAAA IPs (IPv4 first).
// Cached results bypass the network entirely.
func (r *DohResolver) LookupIPAddr(ctx context.Context, host string) ([]net.IP, error) {
	if ip := net.ParseIP(host); ip != nil {
		return []net.IP{ip}, nil
	}
	if ips, ok := r.cache.get(host); ok {
		return ips, nil
	}

	type res struct {
		ips []net.IP
		ttl time.Duration
		err error
	}
	results := make(chan res, 2)
	for _, qt := range [...]uint16{dns.TypeA, dns.TypeAAAA} {
		go func(qtype uint16) {
			ips, ttl, err := r.queryIPs(ctx, host, qtype)
			results <- res{ips, ttl, err}
		}(qt)
	}

	var (
		all     []net.IP
		lastErr error
		minTTL  = dohCacheMaxTTL
	)
	for range 2 {
		rr := <-results
		if rr.err != nil {
			lastErr = rr.err
			continue
		}
		all = append(all, rr.ips...)
		if rr.ttl > 0 && rr.ttl < minTTL {
			minTTL = rr.ttl
		}
	}
	if len(all) == 0 {
		if lastErr == nil {
			lastErr = fmt.Errorf("doh: no records for %s", host)
		}
		return nil, lastErr
	}

	// IPv4 before IPv6 — better compat with mobile IPv4-only CGNAT.
	sort.SliceStable(all, func(i, j int) bool {
		return (all[i].To4() != nil) && (all[j].To4() == nil)
	})

	if minTTL < dohCacheMinTTL {
		minTTL = dohCacheMinTTL
	}
	r.cache.set(host, all, minTTL)
	return all, nil
}

// queryIPs issues one DoH query for qtype, walking endpoints until one
// succeeds, and parses the wire reply into IPs + min TTL.
func (r *DohResolver) queryIPs(ctx context.Context, host string, qtype uint16) ([]net.IP, time.Duration, error) {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(host), qtype)
	m.Id = 0 // RFC 8484 §4.1 — zero ID is cache-friendly on shared caches.
	m.RecursionDesired = true
	wire, err := m.Pack()
	if err != nil {
		return nil, 0, fmt.Errorf("doh: pack query: %w", err)
	}

	body, ep, err := r.forwardRaw(ctx, wire)
	if err != nil {
		return nil, 0, err
	}
	ips, ttl, err := parseAnswer(body)
	if err != nil {
		return nil, 0, fmt.Errorf("doh: parse %s: %w", ep.Hostname, err)
	}
	log.Printf("[DoH] %s %s via %s → %d IPs (ttl %s)", host, dns.TypeToString[qtype], ep.Hostname, len(ips), ttl)
	return ips, ttl, nil
}

// parseAnswer decodes a DNS wire reply into A/AAAA records and the minimum TTL.
func parseAnswer(body []byte) ([]net.IP, time.Duration, error) {
	reply := new(dns.Msg)
	if err := reply.Unpack(body); err != nil {
		return nil, 0, fmt.Errorf("unpack: %w", err)
	}
	if reply.Rcode != dns.RcodeSuccess {
		return nil, 0, fmt.Errorf("rcode %s", dns.RcodeToString[reply.Rcode])
	}
	var (
		ips    []net.IP
		minTTL uint32
	)
	updateTTL := func(ttl uint32) {
		if minTTL == 0 || ttl < minTTL {
			minTTL = ttl
		}
	}
	for _, ans := range reply.Answer {
		switch a := ans.(type) {
		case *dns.A:
			ips = append(ips, a.A)
			updateTTL(a.Hdr.Ttl)
		case *dns.AAAA:
			ips = append(ips, a.AAAA)
			updateTTL(a.Hdr.Ttl)
		}
	}
	return ips, time.Duration(minTTL) * time.Second, nil
}

// forwardRaw POSTs an opaque DNS-wire query to the configured DoH endpoints
// in order and returns the first successful raw response together with the
// endpoint that produced it. No parsing — useful for the local forwarder
// which needs to pass through whatever the upstream resolver answers
// (RESINFO/HTTPS/SVCB/EDNS options/…).
func (r *DohResolver) forwardRaw(ctx context.Context, query []byte) ([]byte, DohEndpoint, error) {
	if len(r.endpoints) == 0 {
		return nil, DohEndpoint{}, errors.New("doh: no endpoints configured")
	}
	var lastErr error
	for _, ep := range r.endpoints {
		body, err := r.postWire(ctx, ep, query)
		if err != nil {
			log.Printf("[DoH] %s: %v", ep.Hostname, err)
			lastErr = err
			continue
		}
		return body, ep, nil
	}
	return nil, DohEndpoint{}, lastErr
}

// postWire performs a single application/dns-message POST to one endpoint.
func (r *DohResolver) postWire(ctx context.Context, ep DohEndpoint, query []byte) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, "POST", ep.URL, bytes.NewReader(query))
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Content-Type", dohContentType)
	req.Header.Set("Accept", dohContentType)

	resp, err := r.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, resp.Body)
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, dohMaxResponseBytes))
	if err != nil {
		return nil, fmt.Errorf("read body: %w", err)
	}
	return body, nil
}

type dohCacheEntry struct {
	ips    []net.IP
	expiry time.Time
}

type dohCache struct {
	mu sync.RWMutex
	m  map[string]dohCacheEntry
}

func newDohCache() *dohCache {
	return &dohCache{m: make(map[string]dohCacheEntry)}
}

func (c *dohCache) get(host string) ([]net.IP, bool) {
	c.mu.RLock()
	e, ok := c.m[host]
	c.mu.RUnlock()
	if !ok || time.Now().After(e.expiry) {
		return nil, false
	}
	out := make([]net.IP, len(e.ips))
	copy(out, e.ips)
	return out, true
}

func (c *dohCache) set(host string, ips []net.IP, ttl time.Duration) {
	if ttl <= 0 {
		return
	}
	if ttl > dohCacheMaxTTL {
		ttl = dohCacheMaxTTL
	}
	cp := make([]net.IP, len(ips))
	copy(cp, ips)
	c.mu.Lock()
	c.m[host] = dohCacheEntry{ips: cp, expiry: time.Now().Add(ttl)}
	c.mu.Unlock()
}
