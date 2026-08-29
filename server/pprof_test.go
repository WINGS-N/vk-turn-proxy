package main

import "testing"

// A profiler address must only be treated as safe when it really cannot be
// reached from outside the host: the endpoint hands out stacks and heap.
func TestIsLoopbackAddr(t *testing.T) {
	cases := []struct {
		addr string
		want bool
	}{
		{"127.0.0.1:6060", true},
		{"localhost:6060", true},
		{"[::1]:6060", true},
		{"127.0.0.53:6060", true},
		{"0.0.0.0:6060", false},
		{":6060", false},
		{"192.168.1.10:6060", false},
		{"[::]:6060", false},
		{"example.com:6060", false},
		{"nonsense", false},
		{"", false},
	}
	for _, tc := range cases {
		t.Run(tc.addr, func(t *testing.T) {
			if got := isLoopbackAddr(tc.addr); got != tc.want {
				t.Fatalf("isLoopbackAddr(%q) = %v, want %v", tc.addr, got, tc.want)
			}
		})
	}
}
