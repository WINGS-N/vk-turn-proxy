package main

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

// TestTurnUsernameLifetime checks the "expiryUnix:userId" TURN REST username is
// turned into a remaining lifetime with a safety margin, a 1-minute floor for
// already-expired creds, and a default for unparsable input.
func TestTurnUsernameLifetime(t *testing.T) {
	future := fmt.Sprintf("%d:601279409979", time.Now().Add(2*time.Hour).Unix())
	if d := turnUsernameLifetime(future); d <= time.Hour {
		t.Fatalf("future lifetime = %s, want > 1h", d)
	}
	past := fmt.Sprintf("%d:1", time.Now().Add(-time.Hour).Unix())
	if d := turnUsernameLifetime(past); d != time.Minute {
		t.Fatalf("past lifetime = %s, want 1m", d)
	}
	if d := turnUsernameLifetime("not-a-number:1"); d != 8*time.Minute {
		t.Fatalf("garbage lifetime = %s, want 8m", d)
	}
}

// TestVkHashFromLink checks the call join hash is extracted from full URLs (with
// query/fragment/trailing slash stripped) and passed through unchanged when it is
// already a bare hash.
func TestVkHashFromLink(t *testing.T) {
	cases := map[string]string{
		"https://vk.com/call/join/ABC123":      "ABC123",
		"https://vk.com/call/join/ABC123?p=1":  "ABC123",
		"https://vk.com/call/join/ABC123#frag": "ABC123",
		"  https://vk.com/call/join/ABC123/  ": "ABC123",
		"ABC123":                               "ABC123",
	}
	for in, want := range cases {
		if got := vkHashFromLink(in); got != want {
			t.Errorf("vkHashFromLink(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestRandomDeviceIDFormat checks the OK SDK device id is a v4-shaped UUID.
func TestRandomDeviceIDFormat(t *testing.T) {
	id := randomDeviceID()
	if len(id) != 36 {
		t.Fatalf("device id len = %d, want 36 (%q)", len(id), id)
	}
	parts := strings.Split(id, "-")
	if len(parts) != 5 || parts[2][0] != '4' {
		t.Fatalf("device id not uuid-v4 shaped: %q", id)
	}
}
