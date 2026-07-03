// Package relaygrpc serves the Relay management API (proto/control.proto) that
// the wingsv-panel calls to inspect a vk-turn-proxy node and manage its tunnel
// peers. It is a thin adapter over internal/peerstore.
package relaygrpc

import (
	"context"
	"crypto/subtle"
	"strings"

	"github.com/cacggghp/vk-turn-proxy/controlpb"
	"github.com/cacggghp/vk-turn-proxy/internal/peerstore"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
)

type server struct {
	controlpb.UnimplementedRelayServer
	store    *peerstore.Store
	version  string
	sessions func() uint64
	token    string
}

// Options configures the Relay gRPC server.
type Options struct {
	Store    *peerstore.Store
	Version  string
	Sessions func() uint64
	Token    string
	Creds    credentials.TransportCredentials
}

// NewServer builds a grpc.Server serving the Relay service. When Token is set,
// callers must present it as a bearer token; a verified client certificate
// (mTLS) is always accepted.
func NewServer(o Options) *grpc.Server {
	s := &server{store: o.Store, version: o.Version, sessions: o.Sessions, token: o.Token}
	opts := []grpc.ServerOption{grpc.ChainUnaryInterceptor(s.authUnary)}
	if o.Creds != nil {
		opts = append(opts, grpc.Creds(o.Creds))
	}
	gs := grpc.NewServer(opts...)
	controlpb.RegisterRelayServer(gs, s)
	return gs
}

func (s *server) GetStatus(_ context.Context, _ *controlpb.GetStatusRequest) (*controlpb.Status, error) {
	var active uint64
	if s.sessions != nil {
		active = s.sessions()
	}
	return &controlpb.Status{
		Version:        s.version,
		WgInterface:    s.store.Interface(),
		PeerCount:      uint32(s.store.Count()),
		ActiveSessions: active,
	}, nil
}

func (s *server) ListPeers(_ context.Context, _ *controlpb.ListPeersRequest) (*controlpb.Peers, error) {
	peers := s.store.List()
	out := make([]*controlpb.Peer, 0, len(peers))
	for _, p := range peers {
		out = append(out, s.toProto(p, ""))
	}
	return &controlpb.Peers{Peers: out}, nil
}

func (s *server) CreatePeer(_ context.Context, req *controlpb.CreatePeerRequest) (*controlpb.Peer, error) {
	created, err := s.store.Create(req.GetPublicKey(), req.GetAllowedIps())
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}
	return s.toProto(created.Peer, created.PrivateKey), nil
}

func (s *server) DeletePeer(_ context.Context, req *controlpb.DeletePeerRequest) (*controlpb.DeletePeerResponse, error) {
	if !s.store.Delete(req.GetPublicKey()) {
		return nil, status.Error(codes.NotFound, "peer not found")
	}
	return &controlpb.DeletePeerResponse{}, nil
}

func (s *server) toProto(p peerstore.Peer, privateKey string) *controlpb.Peer {
	return &controlpb.Peer{
		PublicKey:       p.PublicKey,
		PrivateKey:      privateKey,
		AllowedIps:      p.AllowedIPs,
		ServerPublicKey: s.store.ServerPublicKey(),
		RxBytes:         p.RxBytes,
		TxBytes:         p.TxBytes,
		CreatedUnix:     p.CreatedUnix,
	}
}

func (s *server) authUnary(ctx context.Context, req any, _ *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
	if s.authorized(ctx) {
		return handler(ctx, req)
	}
	return nil, status.Error(codes.Unauthenticated, "missing or invalid credentials")
}

func (s *server) authorized(ctx context.Context) bool {
	if pr, ok := peer.FromContext(ctx); ok && pr.AuthInfo != nil {
		if ti, ok := pr.AuthInfo.(credentials.TLSInfo); ok && len(ti.State.VerifiedChains) > 0 {
			return true
		}
	}
	if s.token == "" {
		return true
	}
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return false
	}
	for _, v := range md.Get("authorization") {
		if tok, found := strings.CutPrefix(v, "Bearer "); found &&
			subtle.ConstantTimeCompare([]byte(tok), []byte(s.token)) == 1 {
			return true
		}
	}
	return false
}
