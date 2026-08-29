package main

import (
	"fmt"
	"log"
	"os"
	"runtime"
	"strconv"
	"strings"
)

// socketBufferLimits are the kernel knobs capping what a socket may ask for.
// SetReadBuffer / SetWriteBuffer are silently clamped to these, so a relay can
// request four megabytes and quietly get two hundred kilobytes.
var socketBufferLimits = []struct {
	path string
	want int
}{
	{"/proc/sys/net/core/rmem_max", serverUDPReadBufferBytes},
	{"/proc/sys/net/core/wmem_max", serverUDPWriteBufferBytes},
}

// tuneSystemBuffers raises the kernel's ceiling on socket buffers to what the
// relay asks for.
//
// A full receive buffer drops the datagram, and a drop here is not a lost packet
// so much as a lost window: the TCP inside the tunnel reads it as congestion and
// backs off, so a few dropped datagrams cost far more throughput than they carry.
// The default ceiling on most distributions is 208 KiB, which a hundred-megabit
// stream drains in under twenty milliseconds - one scheduling hiccup and the
// buffer overflows.
//
// Only ever raises, never lowers: an operator who has already tuned the box
// higher keeps their value. Needs root, and quietly does nothing without it,
// because the relay is useful either way and this is an optimisation rather than
// a requirement.
func tuneSystemBuffers(disabled bool) {
	if disabled || runtime.GOOS != "linux" {
		return
	}
	for _, limit := range socketBufferLimits {
		current, err := readIntFile(limit.path)
		if err != nil {
			continue
		}
		if current >= limit.want {
			continue
		}
		if writeErr := os.WriteFile(limit.path, []byte(strconv.Itoa(limit.want)), 0o644); writeErr != nil {
			log.Printf("socket buffer ceiling %s stays at %d (want %d): %s",
				limit.path, current, limit.want, writeErr)
			continue
		}
		log.Printf("raised %s from %d to %d", limit.path, current, limit.want)
	}
}

func readIntFile(path string) (int, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}
	value, err := strconv.Atoi(strings.TrimSpace(string(raw)))
	if err != nil {
		return 0, fmt.Errorf("parse %s: %w", path, err)
	}
	return value, nil
}
