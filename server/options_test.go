package main

import (
	"bytes"
	"strings"
	"testing"

	"github.com/cacggghp/vk-turn-proxy/internal/cliutil"
)

func TestParseServerOptionsShowsUsageWithoutArgs(t *testing.T) {
	t.Parallel()

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	_, exitCode := parseServerOptions(nil, "server", &stdout, &stderr)
	if exitCode != 0 {
		t.Fatalf("parseServerOptions() exitCode = %d, want 0", exitCode)
	}
	if got := stdout.String(); !strings.Contains(got, "Usage:\n  server -connect <ip:port> [flags]") {
		t.Fatalf("usage output missing server help text: %q", got)
	}
}

func TestParseServerOptionsRequiresBackend(t *testing.T) {
	t.Parallel()

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	_, exitCode := parseServerOptions([]string{"-listen", "0.0.0.0:56000"}, "server", &stdout, &stderr)
	if exitCode != 2 {
		t.Fatalf("parseServerOptions() exitCode = %d, want 2", exitCode)
	}
	if got := stderr.String(); !strings.Contains(got, "at least one backend is required") {
		t.Fatalf("expected backend error, got %q", got)
	}
}

func TestParseServerOptionsParsesValidArgs(t *testing.T) {
	t.Parallel()

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	opts, exitCode := parseServerOptions([]string{"-connect", "127.0.0.1:51820", "-listen", "0.0.0.0:56000"}, "server", &stdout, &stderr)
	if exitCode != cliutil.ContinueExecution {
		t.Fatalf("parseServerOptions() exitCode = %d, want %d", exitCode, cliutil.ContinueExecution)
	}
	if opts.connect != "127.0.0.1:51820" || opts.listen != "0.0.0.0:56000" {
		t.Fatalf("unexpected options: %+v", opts)
	}
}

// Пул адресов пиров обязан лежать в той же подсети, что и адрес интерфейса:
// иначе клиент получает адрес, который на ноде не маскарадится, хендшейк
// проходит, а трафик наружу не идёт
func TestTunnelCIDRFollowsTheInterfaceAddress(t *testing.T) {
	opts := serverOptions{wgApply: true, wgAddress: "10.67.66.1/24", wgTunnelCIDR: "10.66.66.0/24"}
	alignTunnelCIDR(&opts)
	if opts.wgTunnelCIDR != "10.67.66.0/24" {
		t.Fatalf("пул остался %q, а интерфейс живёт в 10.67.66.0/24", opts.wgTunnelCIDR)
	}
}

func TestTunnelCIDRIsKeptWhenItAlreadyHoldsTheInterface(t *testing.T) {
	opts := serverOptions{wgApply: true, wgAddress: "10.66.66.1/24", wgTunnelCIDR: "10.66.66.0/24"}
	alignTunnelCIDR(&opts)
	if opts.wgTunnelCIDR != "10.66.66.0/24" {
		t.Fatalf("согласованный пул зачем-то переписан на %q", opts.wgTunnelCIDR)
	}
}

// Чужим интерфейсом мы не распоряжаемся, и пул там законно любой
func TestTunnelCIDRIsLeftAloneWithoutWgApply(t *testing.T) {
	opts := serverOptions{wgApply: false, wgAddress: "10.67.66.1/24", wgTunnelCIDR: "10.66.66.0/24"}
	alignTunnelCIDR(&opts)
	if opts.wgTunnelCIDR != "10.66.66.0/24" {
		t.Fatalf("пул чужого интерфейса переписан на %q", opts.wgTunnelCIDR)
	}
}
