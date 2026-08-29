package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestMergeConfigFileSeedsAndOverrides(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.toml")
	body := "" +
		"# vk-turn config\n" +
		"listen = \"0.0.0.0:56000\"\n" +
		"panel-grpc = 'v.wingsnet.org:443'\n" +
		"node-id = \"node-from-file\"  # inline\n" +
		"bogus-key = \"ignored\"\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("WINGS_VKTP_CONFIG", path)

	// node-id passed explicitly must win over the file; listen/panel-grpc come from
	// the file; bogus-key (not a real flag) is dropped.
	merged := mergeConfigFile([]string{"-node-id=explicit"})

	joined := merged
	hasPrefixVal := func(flag, val string) bool {
		for _, a := range joined {
			if a == "-"+flag+"="+val {
				return true
			}
		}
		return false
	}
	if !hasPrefixVal("panel-grpc", "v.wingsnet.org:443") {
		t.Errorf("panel-grpc not seeded from file: %v", merged)
	}
	if !hasPrefixVal("listen", "0.0.0.0:56000") {
		t.Errorf("listen not seeded from file: %v", merged)
	}
	// The explicit flag is last, so it overrides the file-seeded one.
	if merged[len(merged)-1] != "-node-id=explicit" {
		t.Errorf("explicit flag should be last (wins): %v", merged)
	}
	for _, a := range merged {
		if a == "-bogus-key=ignored" {
			t.Errorf("unknown key should be dropped: %v", merged)
		}
	}
}

// A node bootstrapped by connect.sh has a config holding only the panel wiring.
// The relay must leave those lines exactly as written and append the keys the
// file never mentioned, so the node ends up with the same documented template as
// the rest of the fleet.
func TestMigrateFlagsToConfigFillsGapsInPartialFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.toml")
	stub := "" +
		"grpc-token = \"deadbeef\"\n" +
		"panel-grpc = \"v.wingsnet.org:443\"\n" +
		"node-id = \"abc123\"\n"
	if err := os.WriteFile(path, []byte(stub), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("WINGS_VKTP_CONFIG", path)

	migrateFlagsToConfig(serverOptionsToConfigLines(serverOptions{
		grpcToken: "deadbeef",
		panelGRPC: "v.wingsnet.org:443",
		nodeID:    "abc123",
	}))

	out, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	got := string(out)
	if !strings.HasPrefix(got, stub) {
		t.Errorf("operator lines were not preserved verbatim:\n%s", got)
	}
	for _, want := range []string{"# listen =", "# wg-apply =", "# wrap-mode ="} {
		if !strings.Contains(got, want) {
			t.Errorf("missing key %q was not filled in:\n%s", want, got)
		}
	}
	// The keys the stub already set must not be duplicated.
	if n := strings.Count(got, "node-id ="); n != 1 {
		t.Errorf("node-id appears %d times, want 1:\n%s", n, got)
	}

	// Re-running must be a no-op: every key is now mentioned.
	before := got
	migrateFlagsToConfig(serverOptionsToConfigLines(serverOptions{nodeID: "abc123"}))
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(after) != before {
		t.Errorf("second run rewrote the file; want idempotent:\n%s", string(after))
	}
}

// A relay that owns its WireGuard interface must keep the same identity across
// restarts: a fresh key every start invalidates every client already provisioned
// against the old public key, with no way for them to recover.
func TestWgKeyFilePathPersistsForOwnWg(t *testing.T) {
	if got := wgKeyFilePath(serverOptions{wgApply: true}); got == "" {
		t.Error("own-wg relay got an ephemeral key file; its public key would change on every restart")
	}
	explicit := wgKeyFilePath(serverOptions{wgApply: true, wgKeyFile: "/custom/path.key"})
	if explicit != "/custom/path.key" {
		t.Errorf("explicit -wg-key-file = %q, want it to win", explicit)
	}
	// A relay forwarding to someone else's WireGuard owns no identity to keep.
	if got := wgKeyFilePath(serverOptions{wgApply: false}); got != "" {
		t.Errorf("forwarding relay got key file %q, want none", got)
	}
}
