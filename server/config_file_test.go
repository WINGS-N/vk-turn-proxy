package main

import (
	"os"
	"path/filepath"
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
