package main

import (
	"bytes"
	"strings"
	"testing"

	"github.com/cacggghp/vk-turn-proxy/internal/cliutil"
)

func TestParseClientOptionsShowsUsageWithoutArgs(t *testing.T) {
	t.Parallel()

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	_, exitCode := parseClientOptions(nil, "client", &stdout, &stderr)
	if exitCode != 0 {
		t.Fatalf("parseClientOptions() exitCode = %d, want 0", exitCode)
	}
	if stderr.Len() != 0 {
		t.Fatalf("expected no stderr output, got %q", stderr.String())
	}
	if got := stdout.String(); !strings.Contains(got, "Usage:\n  client -peer <host:port> -vk-link <link> [flags]") {
		t.Fatalf("usage output missing client help text: %q", got)
	}
}

func TestParseClientOptionsRequiresPeer(t *testing.T) {
	t.Parallel()

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	_, exitCode := parseClientOptions([]string{"-vk-link", "https://vk.com/call/join/test"}, "client", &stdout, &stderr)
	if exitCode != 2 {
		t.Fatalf("parseClientOptions() exitCode = %d, want 2", exitCode)
	}
	if got := stderr.String(); !strings.Contains(got, "error: -peer is required") {
		t.Fatalf("expected missing peer error, got %q", got)
	}
}

func TestParseClientOptionsParsesValidVKArgs(t *testing.T) {
	t.Parallel()

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	opts, exitCode := parseClientOptions([]string{"-peer", "127.0.0.1:56000", "-vk-link", "https://vk.com/call/join/test", "-listen", "127.0.0.1:9001"}, "client", &stdout, &stderr)
	if exitCode != cliutil.ContinueExecution {
		t.Fatalf("parseClientOptions() exitCode = %d, want %d", exitCode, cliutil.ContinueExecution)
	}
	if opts.peerAddr != "127.0.0.1:56000" || opts.listen != "127.0.0.1:9001" {
		t.Fatalf("unexpected options: %+v", opts)
	}
}
