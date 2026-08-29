package main

import (
	"context"
	"log"
	"net"
	"net/http"
	"net/http/pprof"
	"runtime"
	"strings"
	"time"
)

// startProfiler serves the Go runtime profiles on addr until ctx ends.
//
// It is off unless an address is configured, because the endpoint hands out
// goroutine stacks, heap contents and the process command line to anyone who can
// reach it. A non-loopback address is served anyway - the operator may have a
// reason - but it is called out loudly in the log so it cannot happen by
// accident and go unnoticed.
func startProfiler(ctx context.Context, addr string) {
	if addr == "" {
		return
	}
	if !isLoopbackAddr(addr) {
		log.Printf("WARNING: profiler on %s is NOT loopback - it exposes stacks, heap and the command line", addr)
	}

	// Block and mutex profiles are off by default in the runtime; the profiler
	// is worth little without them when the question is where a relay waits.
	runtime.SetBlockProfileRate(blockProfileRate)
	runtime.SetMutexProfileFraction(mutexProfileFraction)

	mux := http.NewServeMux()
	mux.HandleFunc("/debug/pprof/", pprof.Index)
	mux.HandleFunc("/debug/pprof/cmdline", pprof.Cmdline)
	mux.HandleFunc("/debug/pprof/profile", pprof.Profile)
	mux.HandleFunc("/debug/pprof/symbol", pprof.Symbol)
	mux.HandleFunc("/debug/pprof/trace", pprof.Trace)

	server := &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
	}
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdownCtx)
	}()
	go func() {
		log.Printf("Profiler on http://%s/debug/pprof/", addr)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Printf("profiler stopped: %s", err)
		}
	}()
}

const (
	// blockProfileRate samples one blocking event in this many nanoseconds of
	// blocked time. Sampling rather than recording every event keeps the cost
	// off the packet path while still showing where the relay waits.
	blockProfileRate = 10000
	// mutexProfileFraction samples one in this many mutex contentions.
	mutexProfileFraction = 100
)

// isLoopbackAddr reports whether addr names a loopback interface, so serving the
// profiles cannot reach beyond this host.
func isLoopbackAddr(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	if host == "" {
		// An empty host means every interface.
		return false
	}
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
