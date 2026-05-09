package main

import (
	"reflect"
	"testing"
)

func TestSplitUserDnsEntries(t *testing.T) {
	cases := []struct {
		in   string
		want []string
	}{
		{"", nil},
		{"  ", nil},
		{"https://a/dns-query", []string{"https://a/dns-query"}},
		{"https://a, https://b\nhttps://c;https://d", []string{
			"https://a", "https://b", "https://c", "https://d",
		}},
		{"\n  77.88.8.8 \n  ;  ", []string{"77.88.8.8"}},
	}
	for _, tc := range cases {
		got := splitUserDnsEntries(tc.in)
		if !equalStringSlice(got, tc.want) {
			t.Errorf("splitUserDnsEntries(%q) = %v, want %v", tc.in, got, tc.want)
		}
	}
}

func TestParseUserDnsEntry_UdpVariants(t *testing.T) {
	cases := []struct {
		in        string
		wantIP    string
		wantOk    bool
		shouldDoH bool
	}{
		{"77.88.8.8", "77.88.8.8:53", true, false},
		{"77.88.8.8:5353", "77.88.8.8:5353", true, false},
		{"udp://1.1.1.1", "1.1.1.1:53", true, false},
		{"UDP://1.1.1.1:53", "1.1.1.1:53", true, false},
		{"[2001:4860:4860::8888]:53", "[2001:4860:4860::8888]:53", true, false},
		{"udp://example.com", "", false, false}, // hostname not allowed for plain UDP
		{"tls://77.88.8.8", "", false, false},   // DoT rejected with log
		{"", "", false, false},
	}
	for _, tc := range cases {
		doh, udp, ok := parseUserDnsEntry(tc.in)
		if ok != tc.wantOk {
			t.Errorf("parseUserDnsEntry(%q) ok=%v want=%v", tc.in, ok, tc.wantOk)
		}
		if udp != tc.wantIP {
			t.Errorf("parseUserDnsEntry(%q) udp=%q want=%q", tc.in, udp, tc.wantIP)
		}
		if (doh != nil) != tc.shouldDoH {
			t.Errorf("parseUserDnsEntry(%q) doh-presence=%v want=%v", tc.in, doh != nil, tc.shouldDoH)
		}
	}
}

func TestParseUserDnsEntry_DohWithLiteralIP(t *testing.T) {
	doh, udp, ok := parseUserDnsEntry("https://77.88.8.8/dns-query")
	if !ok || doh == nil {
		t.Fatalf("expected DoH endpoint for literal IP url, got ok=%v doh=%v", ok, doh)
	}
	if udp != "" {
		t.Errorf("unexpected UDP entry: %q", udp)
	}
	if doh.Hostname != "77.88.8.8" {
		t.Errorf("hostname=%q want 77.88.8.8", doh.Hostname)
	}
	if !reflect.DeepEqual(doh.BootstrapIPs, []string{"77.88.8.8"}) {
		t.Errorf("bootstrap=%v want [77.88.8.8]", doh.BootstrapIPs)
	}
	if doh.URL != "https://77.88.8.8/dns-query" {
		t.Errorf("url=%q want https://77.88.8.8/dns-query", doh.URL)
	}
}

func TestApplyUserDns_PrependsKeepingDefaults(t *testing.T) {
	origDoh := append([]DohEndpoint{}, defaultDohEndpoints...)
	origUdp := append([]string{}, udpDNSServers...)
	defer func() {
		defaultDohEndpoints = origDoh
		udpDNSServers = origUdp
	}()

	applyUserDns("https://77.88.8.8/dns-query, 9.9.9.9")
	if len(defaultDohEndpoints) != len(origDoh)+1 {
		t.Errorf("DoH list grew by %d, want 1", len(defaultDohEndpoints)-len(origDoh))
	}
	if defaultDohEndpoints[0].URL != "https://77.88.8.8/dns-query" {
		t.Errorf("DoH[0]=%q, want user-supplied first", defaultDohEndpoints[0].URL)
	}
	if len(udpDNSServers) != len(origUdp)+1 {
		t.Errorf("UDP list grew by %d, want 1", len(udpDNSServers)-len(origUdp))
	}
	if udpDNSServers[0] != "9.9.9.9:53" {
		t.Errorf("UDP[0]=%q, want 9.9.9.9:53 first", udpDNSServers[0])
	}
}

func equalStringSlice(a, b []string) bool {
	if len(a) == 0 && len(b) == 0 {
		return true
	}
	return reflect.DeepEqual(a, b)
}
