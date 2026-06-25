package main

import (
	"context"
	"reflect"
	"testing"
	"time"
)

// TestTurnURLsToAddresses verifies turn:/turns: URLs are normalized to host:port
// addresses (query stripped) and blanks are dropped.
func TestTurnURLsToAddresses(t *testing.T) {
	in := []string{
		"turn:1.2.3.4:3478?transport=udp",
		"turns:5.6.7.8:5349",
		"  ",
		"",
		"turn:9.10.11.12:3478",
	}
	got := turnURLsToAddresses(in)
	want := []string{"1.2.3.4:3478", "5.6.7.8:5349", "9.10.11.12:3478"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("turnURLsToAddresses = %v, want %v", got, want)
	}
}

// TestInjectAndGetTurnCreds verifies creds round-trip through the per-link cache
// and that an incomplete set (no addresses) is rejected.
func TestInjectAndGetTurnCreds(t *testing.T) {
	link := "inject-link"
	injectTurnCreds(link, "alice", "secret", []string{"turn:1.2.3.4:3478?transport=udp", "turns:5.6.7.8:5349"})
	user, pass, addrs, ok := getInjectedTurnCreds(link)
	if !ok {
		t.Fatalf("expected creds present")
	}
	if user != "alice" || pass != "secret" {
		t.Fatalf("creds mismatch: user=%q pass=%q", user, pass)
	}
	if len(addrs) != 2 || addrs[0] != "1.2.3.4:3478" || addrs[1] != "5.6.7.8:5349" {
		t.Fatalf("addrs mismatch: %v", addrs)
	}

	// Incomplete creds (no usable urls) must not be cached.
	injectTurnCreds("empty-link", "u", "p", nil)
	if _, _, _, ok := getInjectedTurnCreds("empty-link"); ok {
		t.Fatalf("incomplete creds should not be cached")
	}
}

// TestVkJoinURLForHash verifies the desktop join URL is built from a hash.
func TestVkJoinURLForHash(t *testing.T) {
	if got := vkJoinURLForHash("abc123"); got != "https://vk.com/call/join/abc123" {
		t.Fatalf("vkJoinURLForHash = %q", got)
	}
}

// TestStdinReaderDeliversCreds verifies a vk_account_creds delivery signals the
// shared per-link auth with the parsed creds (addresses normalized).
func TestStdinReaderDeliversCreds(t *testing.T) {
	link := "stdin-creds-link"
	handle := acquireAccountAuth(link)
	if !handle.leader {
		t.Fatalf("first acquire must be leader")
	}
	auth := handle.auth

	// Simulate what StartAccountCredsStdinReader does on a non-cancel line.
	line := vkAccountCredsLine{
		Type:       "vk_account_creds",
		Link:       link,
		Username:   "bob",
		Credential: "pw",
		URLs:       []string{"turn:1.2.3.4:3478?transport=udp", "turns:5.6.7.8:5349"},
	}
	addresses := turnURLsToAddresses(line.URLs)
	injectTurnCreds(line.Link, line.Username, line.Credential, line.URLs)
	resolveAccountAuth(line.Link, accountCredsResult{creds: injectedTurnCreds{
		user:  line.Username,
		pass:  line.Credential,
		addrs: cloneAddrs(addresses),
	}})

	select {
	case <-auth.done:
		res := auth.res
		if res.err != nil {
			t.Fatalf("unexpected err: %s", res.err)
		}
		if res.creds.user != "bob" || res.creds.pass != "pw" {
			t.Fatalf("creds mismatch: %+v", res.creds)
		}
		if len(res.creds.addrs) != 2 {
			t.Fatalf("addrs mismatch: %v", res.creds.addrs)
		}
	case <-time.After(time.Second):
		t.Fatalf("auth was not resolved")
	}
}

// TestStdinReaderCancelSignalsError verifies a cancel aborts the shared auth
// with an error.
func TestStdinReaderCancelSignalsError(t *testing.T) {
	link := "stdin-cancel-link"
	handle := acquireAccountAuth(link)
	if !handle.leader {
		t.Fatalf("first acquire must be leader")
	}
	auth := handle.auth

	resolveAccountAuth(link, accountCredsResult{err: context.Canceled})

	select {
	case <-auth.done:
		if auth.res.err == nil {
			t.Fatalf("expected cancel error")
		}
	case <-time.After(time.Second):
		t.Fatalf("auth was not resolved on cancel")
	}
}

// TestAccountAuthSharedAcrossWorkers verifies that for a single link only the
// first caller is the leader (emits), subsequent callers share the same done
// channel, and one resolve releases every waiter with the same creds.
func TestAccountAuthSharedAcrossWorkers(t *testing.T) {
	link := "shared-link"
	leader := acquireAccountAuth(link)
	if !leader.leader {
		t.Fatalf("first acquire must be leader")
	}

	const followers = 3
	auths := make([]*accountAuth, followers)
	for i := range auths {
		h := acquireAccountAuth(link)
		if h.leader {
			t.Fatalf("follower %d must not be leader", i)
		}
		if h.auth != leader.auth {
			t.Fatalf("follower %d must share the leader auth pointer", i)
		}
		auths[i] = h.auth
	}

	// One resolve must release the leader and every follower with the creds.
	resolveAccountAuth(link, accountCredsResult{creds: injectedTurnCreds{
		user: "carol", pass: "pw", addrs: []string{"1.2.3.4:3478"},
	}})

	all := append([]*accountAuth{leader.auth}, auths...)
	for i, a := range all {
		select {
		case <-a.done:
			if a.res.creds.user != "carol" {
				t.Fatalf("waiter %d got wrong creds: %+v", i, a.res.creds)
			}
		case <-time.After(time.Second):
			t.Fatalf("waiter %d was not released", i)
		}
	}

	// After resolution the in-flight guard is cleared, so a fresh acquire is a
	// new leader able to re-emit.
	again := acquireAccountAuth(link)
	if !again.leader {
		t.Fatalf("after resolution a new acquire must be leader")
	}
	resolveAccountAuth(link, accountCredsResult{err: context.Canceled})
}

// TestAccountAuthPendingCounter verifies the session-timing guard counter
// composes across concurrent waits.
func TestAccountAuthPendingCounter(t *testing.T) {
	if isAccountAuthPending() {
		t.Fatalf("expected no pending auth at start")
	}
	beginAccountAuthWait()
	beginAccountAuthWait()
	if !isAccountAuthPending() {
		t.Fatalf("expected pending auth after begin")
	}
	endAccountAuthWait()
	if !isAccountAuthPending() {
		t.Fatalf("still expected pending auth with one outstanding")
	}
	endAccountAuthWait()
	if isAccountAuthPending() {
		t.Fatalf("expected no pending auth after both end")
	}
}
