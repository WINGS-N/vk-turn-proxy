package main

import (
	"context"
	"crypto/subtle"
	"fmt"
	"log"
	"net"
	"os"
	"strings"
	"sync"
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

// ConfigureFunc receives the runtime configuration the host app used to pass as
// CLI flags. It returns an error string (empty on success) surfaced to the app.
type ConfigureFunc func(*appcontrolpb.ConfigureRequest) string

type appControlServer struct {
	appcontrolpb.UnimplementedAppControlServer
	setCookies func(cookies, userAgent string)
	provision  ProvisionFunc
	configure  ConfigureFunc
}

func (s *appControlServer) Configure(_ context.Context, req *appcontrolpb.ConfigureRequest) (*appcontrolpb.ConfigureResponse, error) {
	log.Printf("app-control: Configure peer=%q listen=%q session_mode=%q vk_auth=%q", req.GetPeer(), req.GetListen(), req.GetSessionMode(), req.GetVkAuth())
	if s.configure == nil {
		return &appcontrolpb.ConfigureResponse{Error: "configuration is not accepted in this mode"}, nil
	}
	return &appcontrolpb.ConfigureResponse{Error: s.configure(req)}, nil
}

func (s *appControlServer) GetTelemetry(context.Context, *appcontrolpb.GetTelemetryRequest) (*appcontrolpb.Telemetry, error) {
	// The same counter is still printed as a PROXY_EVENT telemetry line for the
	// logs; this just lets the app read it over gRPC instead of scraping stdout.
	return &appcontrolpb.Telemetry{ConnectedStreams: int64(connectedStreams.Load())}, nil
}

func (s *appControlServer) StreamTelemetry(_ *appcontrolpb.StreamTelemetryRequest, stream grpc.ServerStreamingServer[appcontrolpb.Telemetry]) error {
	// Push the current value immediately, then one message per change - event-driven,
	// so the app sees stream-count updates with no poll latency.
	if err := stream.Send(&appcontrolpb.Telemetry{ConnectedStreams: int64(connectedStreams.Load())}); err != nil {
		return err
	}
	ch := telemetryHub.subscribe()
	defer telemetryHub.unsubscribe(ch)
	ctx := stream.Context()
	for {
		select {
		case <-ctx.Done():
			return nil
		case v, ok := <-ch:
			if !ok {
				return nil
			}
			if err := stream.Send(&appcontrolpb.Telemetry{ConnectedStreams: int64(v)}); err != nil {
				return err
			}
		}
	}
}

// telemetryHub fans the connected-stream count out to every active StreamTelemetry
// subscriber. Publishes are non-blocking: a subscriber that falls behind simply
// coalesces to the next value it reads (the counter is a snapshot, not a log).
type telemetryBroadcaster struct {
	mu   sync.Mutex
	subs map[chan int32]struct{}
}

var telemetryHub = &telemetryBroadcaster{subs: make(map[chan int32]struct{})}

func (h *telemetryBroadcaster) publish(v int32) {
	h.mu.Lock()
	defer h.mu.Unlock()
	for ch := range h.subs {
		// Drain a stale pending value so the newest snapshot is what waits.
		select {
		case <-ch:
		default:
		}
		select {
		case ch <- v:
		default:
		}
	}
}

func (h *telemetryBroadcaster) subscribe() chan int32 {
	ch := make(chan int32, 1)
	h.mu.Lock()
	h.subs[ch] = struct{}{}
	h.mu.Unlock()
	return ch
}

func (h *telemetryBroadcaster) unsubscribe(ch chan int32) {
	h.mu.Lock()
	delete(h.subs, ch)
	h.mu.Unlock()
	close(ch)
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
//
// peerUID is the uid the socket must accept and be owned by. A negative value
// uses this process's own uid (the common in-process case). On the root/kernel-WG
// path the relay runs under su as uid 0 while the host app connects as its own
// uid, so the app passes its uid here: the socket is chowned to it (root can) and
// the peer-cred check accepts it, otherwise the app could never reach the relay.
func StartAppControl(socketPath, token string, peerUID int, setCookies func(cookies, ua string), provision ProvisionFunc, configure ConfigureFunc) (*grpc.Server, error) {
	_ = os.Remove(socketPath)
	lis, err := net.Listen("unix", socketPath)
	if err != nil {
		return nil, fmt.Errorf("app-control: listen %s: %w", socketPath, err)
	}
	allowedUID := uint32(os.Getuid())
	if peerUID >= 0 {
		allowedUID = uint32(peerUID)
	}
	if err := os.Chmod(socketPath, 0o600); err != nil {
		_ = lis.Close()
		return nil, fmt.Errorf("app-control: chmod socket: %w", err)
	}
	// Hand ownership to the connecting uid when it differs from ours (root path),
	// so the 0600 socket is reachable by the app that will connect to it.
	if allowedUID != uint32(os.Getuid()) {
		if err := os.Chown(socketPath, int(allowedUID), -1); err != nil {
			_ = lis.Close()
			return nil, fmt.Errorf("app-control: chown socket to uid %d: %w", allowedUID, err)
		}
	}
	lis = newPeerCredListener(lis, allowedUID)
	gs := grpc.NewServer(grpc.ChainUnaryInterceptor(appControlAuth(token)))
	appcontrolpb.RegisterAppControlServer(gs, &appControlServer{setCookies: setCookies, provision: provision, configure: configure})
	appControlActive.Store(true)
	go func() { _ = gs.Serve(lis) }()
	return gs, nil
}
