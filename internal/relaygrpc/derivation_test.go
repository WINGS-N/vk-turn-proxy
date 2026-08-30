package relaygrpc

import "testing"

// The panel opens a fresh connection per poll, so keying the "seen" set by the
// full address would turn a once-per-peer migration note into a log line every
// few seconds, forever.
func TestPeerHostDropsTheEphemeralPort(t *testing.T) {
	for _, tc := range []struct{ addr, want string }{
		{"127.0.0.1:47528", "127.0.0.1"},
		{"127.0.0.1:52274", "127.0.0.1"},
		{"[2001:db8::1]:9000", "2001:db8::1"},
		{"/run/vktp.sock", "/run/vktp.sock"},
	} {
		if got := peerHost(tc.addr); got != tc.want {
			t.Errorf("peerHost(%q) = %q, want %q", tc.addr, got, tc.want)
		}
	}
}
