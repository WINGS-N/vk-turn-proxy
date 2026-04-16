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
