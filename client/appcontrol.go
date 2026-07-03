package main

import (
	"context"
	"crypto/subtle"
	"fmt"
	"log"
	"net"
	"os"
	"strings"
	"sync/atomic"

	"github.com/cacggghp/vk-turn-proxy/appcontrolpb"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// ProvisionFunc performs the DTLS PROVISION exchange through VK TURN and returns
// the WireGuard config the node minted for the client.
type ProvisionFunc func(ctx context.Context, clientID string, token []byte, hwid string, localPort uint32) (*appcontrolpb.WireguardConfig, error)

// appControlActive is set once the AppControl IPC is serving. While active the
// relay stops putting the VK cookie value on stdout (the app pulls it over gRPC
// with GetVKCookies instead); the stdout event path itself stays in the binary.
var appControlActive atomic.Bool

type appControlServer struct {
	appcontrolpb.UnimplementedAppControlServer
	setCookies func(cookies, userAgent string)
	provision  ProvisionFunc
}

func (s *appControlServer) GetVKCookies(context.Context, *appcontrolpb.GetVKCookiesRequest) (*appcontrolpb.GetVKCookiesResponse, error) {
	cookies, ua, _ := getVkSession()
	log.Printf("app-control: GetVKCookies (cookies=%d bytes)", len(cookies))
	return &appcontrolpb.GetVKCookiesResponse{Cookies: cookies, UserAgent: ua}, nil
}

func (s *appControlServer) SetVKCookies(_ context.Context, req *appcontrolpb.SetVKCookiesRequest) (*appcontrolpb.SetVKCookiesResponse, error) {
	// gRPC exchanges are logged, but the cookie value is a secret: log only its
	// length so it never reaches stdout / logcat.
	log.Printf("app-control: SetVKCookies (cookies=%d bytes, ua=%q)", len(req.GetCookies()), req.GetUserAgent())
	if s.setCookies != nil {
		s.setCookies(req.GetCookies(), req.GetUserAgent())
	}
	return &appcontrolpb.SetVKCookiesResponse{}, nil
}

func (s *appControlServer) Provision(ctx context.Context, req *appcontrolpb.ProvisionRequest) (*appcontrolpb.ProvisionResponse, error) {
	// The panel token is a secret; log the client id and outcome only.
	log.Printf("app-control: Provision client_id=%q hwid=%q", req.GetClientId(), req.GetHwid())
	if s.provision == nil {
		return &appcontrolpb.ProvisionResponse{Error: "provisioning is not available"}, nil
	}
	wg, err := s.provision(ctx, req.GetClientId(), req.GetToken(), req.GetHwid(), req.GetLocalPort())
	if err != nil {
		log.Printf("app-control: Provision client_id=%q failed: %v", req.GetClientId(), err)
		return &appcontrolpb.ProvisionResponse{Error: err.Error()}, nil
	}
	log.Printf("app-control: Provision client_id=%q ok (address=%s)", req.GetClientId(), wg.GetAddress())
	return &appcontrolpb.ProvisionResponse{Wg: wg}, nil
}

func appControlAuth(token string) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, _ *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		if token == "" {
			return handler(ctx, req)
		}
		if md, ok := metadata.FromIncomingContext(ctx); ok {
			for _, v := range md.Get("authorization") {
				if presented, found := strings.CutPrefix(v, "Bearer "); found &&
					subtle.ConstantTimeCompare([]byte(presented), []byte(token)) == 1 {
					return handler(ctx, req)
				}
			}
		}
		return nil, status.Error(codes.Unauthenticated, "invalid app-control token")
	}
}

// StartAppControl serves the AppControl IPC on a unix socket. Access is
// restricted three ways: the socket is created 0600 in the caller-provided path
// (the app's private dir), peers with a different UID are rejected (linux), and
// a non-empty token is additionally required as a bearer credential.
func StartAppControl(socketPath, token string, setCookies func(cookies, ua string), provision ProvisionFunc) (*grpc.Server, error) {
	_ = os.Remove(socketPath)
	lis, err := net.Listen("unix", socketPath)
	if err != nil {
		return nil, fmt.Errorf("app-control: listen %s: %w", socketPath, err)
	}
	if err := os.Chmod(socketPath, 0o600); err != nil {
		_ = lis.Close()
		return nil, fmt.Errorf("app-control: chmod socket: %w", err)
	}
	lis = newPeerCredListener(lis, uint32(os.Getuid()))
	gs := grpc.NewServer(grpc.ChainUnaryInterceptor(appControlAuth(token)))
	appcontrolpb.RegisterAppControlServer(gs, &appControlServer{setCookies: setCookies, provision: provision})
	appControlActive.Store(true)
	go func() { _ = gs.Serve(lis) }()
	return gs, nil
}
