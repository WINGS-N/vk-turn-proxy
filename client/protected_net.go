package main

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gorilla/websocket"
)

var defaultResolverAddrs = []string{
	"77.88.8.8:53",
	"77.88.8.1:53",
	"8.8.8.8:53",
	"8.8.4.4:53",
	"1.1.1.1:53",
}

type protectedResolver struct {
	resolverAddrs []string
	protectBridge *protectBridge
}

func newProtectedResolver(protect *protectBridge, resolverAddrs []string) *protectedResolver {
	addrs := resolverAddrs
	if len(addrs) == 0 {
		addrs = defaultResolverAddrs
	}
	return &protectedResolver{
		resolverAddrs: addrs,
		protectBridge: protect,
	}
}

func (r *protectedResolver) dialer() *net.Dialer {
	dialer := &net.Dialer{}
	if r != nil && r.protectBridge != nil {
		dialer.Control = r.protectBridge.Control
	}
	return dialer
}

func (r *protectedResolver) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, fmt.Errorf("split host/port: %w", err)
	}
	if ip := net.ParseIP(host); ip != nil {
		return r.dialer().DialContext(ctx, network, addr)
	}

	ips, err := r.LookupIPAddr(ctx, host)
	if err != nil {
		return nil, err
	}

	var lastErr error
	for _, ip := range ips {
		conn, dialErr := r.dialer().DialContext(ctx, network, net.JoinHostPort(ip.IP.String(), port))
		if dialErr == nil {
			return conn, nil
		}
		lastErr = dialErr
	}
	if lastErr != nil {
		return nil, lastErr
	}
	return nil, fmt.Errorf("no addresses resolved for %s", addr)
}

func (r *protectedResolver) LookupIPAddr(ctx context.Context, host string) ([]net.IPAddr, error) {
	if ip := net.ParseIP(host); ip != nil {
		return []net.IPAddr{{IP: ip}}, nil
	}

	var lastErr error
	for _, resolverAddr := range r.resolverAddrs {
		resolver := &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
				return r.dialer().DialContext(ctx, network, resolverAddr)
			},
		}
		ips, err := resolver.LookupIPAddr(ctx, host)
		if err == nil && len(ips) > 0 {
			return ips, nil
		}
		lastErr = err
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("dns lookup failed for %s", host)
	}
	return nil, lastErr
}

func (r *protectedResolver) ResolveUDPAddr(ctx context.Context, hostPort string) (*net.UDPAddr, error) {
	host, port, err := net.SplitHostPort(hostPort)
	if err != nil {
		return nil, err
	}
	ips, err := r.LookupIPAddr(ctx, host)
	if err != nil {
		return nil, err
	}
	if len(ips) == 0 {
		return nil, fmt.Errorf("no ip addresses for %s", host)
	}
	portInt, err := strconv.Atoi(port)
	if err != nil {
		return nil, fmt.Errorf("parse port: %w", err)
	}
	return &net.UDPAddr{IP: ips[0].IP, Port: portInt}, nil
}

func (r *protectedResolver) newHTTPClient(timeout time.Duration) *http.Client {
	return &http.Client{
		Timeout:   timeout,
		Transport: r.newHTTPTransport(),
	}
}

func (r *protectedResolver) newWebsocketDialer(timeout time.Duration) *websocket.Dialer {
	return &websocket.Dialer{
		HandshakeTimeout: timeout,
		NetDialContext:   r.DialContext,
		Proxy:            http.ProxyFromEnvironment,
	}
}

func (r *protectedResolver) newHTTPTransport() *http.Transport {
	return &http.Transport{
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 100,
		IdleConnTimeout:     90 * time.Second,
		DialContext:         r.DialContext,
		Proxy:               nil,
	}
}

func (r *protectedResolver) newProtectedSystemHTTPTransport() *http.Transport {
	return &http.Transport{
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 100,
		IdleConnTimeout:     90 * time.Second,
		DialContext:         r.dialer().DialContext,
		Proxy:               nil,
	}
}

func normalizeJoinLink(raw string) string {
	if raw == "" {
		return raw
	}
	raw = strings.TrimSpace(raw)
	if idx := strings.IndexAny(raw, "/?#"); idx != -1 {
		raw = raw[:idx]
	}
	return raw
}
