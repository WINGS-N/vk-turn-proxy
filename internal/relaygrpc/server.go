// Package relaygrpc serves the Relay management API (proto/control.proto) that
// the wingsv-panel calls to inspect a vk-turn-proxy node and manage its tunnel
// peers. It is a thin adapter over internal/peerstore.
package relaygrpc

import (
	"context"
	"crypto/subtle"
	"strings"
	"time"

	"github.com/cacggghp/vk-turn-proxy/controlpb"
	"github.com/cacggghp/vk-turn-proxy/internal/peerstore"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
)

// Flow is one active relay stream.
type Flow struct {
	SessionID   string
	StreamID    uint32
	ClientIP    string
	Remote      string
	Protocol    string
	Version     uint32
	RxBytes     uint64
	TxBytes     uint64
	RxRate      uint64
	TxRate      uint64
	StartedUnix int64
}

// FlowStats aggregates the node's live relay activity.
type FlowStats struct {
	ActiveStreams             uint32
	ActiveSessions            uint32
	TotalSessions             uint64
	AvgSessionLifetimeSeconds float64
	ServerRxBytes             uint64
	ServerTxBytes             uint64
	StreamsByProtocol         map[string]uint32
}

// FlowProvider exposes the node's active flows and aggregate stats. The server
// TUI registry implements it.
type FlowProvider interface {
	Flows() []Flow
	FlowStats() FlowStats
}

type server struct {
	controlpb.UnimplementedRelayServer
	store    *peerstore.Store
	version  string
	sessions func() uint64
	token    string
	flows    FlowProvider
	listen   string
}

// Options configures the Relay gRPC server.
type Options struct {
	Store    *peerstore.Store
	Version  string
	Sessions func() uint64
	Token    string
	Creds    credentials.TransportCredentials
	Flows    FlowProvider
	// Listen is the relay's DTLS data-plane listen address, reported in Status so
	// the panel can derive the endpoint apps dial.
	Listen string
}

// NewServer builds a grpc.Server serving the Relay service. When Token is set,
// callers must present it as a bearer token; a verified client certificate
// (mTLS) is always accepted.
// flowStatsStreamInterval is how often StreamFlowStats pushes a snapshot. One
// second gives the panel responsive rx/tx rates without flooding the link.
const flowStatsStreamInterval = time.Second

func NewServer(o Options) *grpc.Server {
	s := &server{store: o.Store, version: o.Version, sessions: o.Sessions, token: o.Token, flows: o.Flows, listen: o.Listen}
	opts := []grpc.ServerOption{
		grpc.ChainUnaryInterceptor(s.authUnary),
		grpc.ChainStreamInterceptor(s.authStream),
	}
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
		ListenEndpoint: s.listen,
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

func (s *server) ListFlows(_ context.Context, _ *controlpb.ListFlowsRequest) (*controlpb.Flows, error) {
	return s.flowsProto(), nil
}

// StreamFlows pushes the active-flow list immediately, then once per tick, so the
// panel's flow graph updates live without re-dialing.
func (s *server) StreamFlows(_ *controlpb.ListFlowsRequest, stream grpc.ServerStreamingServer[controlpb.Flows]) error {
	ticker := time.NewTicker(flowStatsStreamInterval)
	defer ticker.Stop()
	ctx := stream.Context()
	if err := stream.Send(s.flowsProto()); err != nil {
		return err
	}
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			if err := stream.Send(s.flowsProto()); err != nil {
				return err
			}
		}
	}
}

func (s *server) flowsProto() *controlpb.Flows {
	if s.flows == nil {
		return &controlpb.Flows{}
	}
	src := s.flows.Flows()
	out := make([]*controlpb.Flow, 0, len(src))
	for _, f := range src {
		out = append(out, &controlpb.Flow{
			SessionId:   f.SessionID,
			StreamId:    f.StreamID,
			ClientIp:    f.ClientIP,
			Remote:      f.Remote,
			Protocol:    f.Protocol,
			Version:     f.Version,
			RxBytes:     f.RxBytes,
			TxBytes:     f.TxBytes,
			RxRate:      f.RxRate,
			TxRate:      f.TxRate,
			StartedUnix: f.StartedUnix,
		})
	}
	return &controlpb.Flows{Flows: out}
}

func (s *server) GetFlowStats(_ context.Context, _ *controlpb.GetFlowStatsRequest) (*controlpb.FlowStats, error) {
	return s.flowStatsProto(), nil
}

func (s *server) flowStatsProto() *controlpb.FlowStats {
	if s.flows == nil {
		return &controlpb.FlowStats{}
	}
	st := s.flows.FlowStats()
	return &controlpb.FlowStats{
		ActiveStreams:             st.ActiveStreams,
		ActiveSessions:            st.ActiveSessions,
		TotalSessions:             st.TotalSessions,
		AvgSessionLifetimeSeconds: st.AvgSessionLifetimeSeconds,
		ServerRxBytes:             st.ServerRxBytes,
		ServerTxBytes:             st.ServerTxBytes,
		StreamsByProtocol:         st.StreamsByProtocol,
	}
}

// StreamFlowStats pushes a snapshot immediately, then one per tick, so the panel
// sees live speed/traffic without re-dialing. The panel derives rx/tx rates from
// the deltas between snapshots.
func (s *server) StreamFlowStats(_ *controlpb.GetFlowStatsRequest, stream grpc.ServerStreamingServer[controlpb.FlowStats]) error {
	ticker := time.NewTicker(flowStatsStreamInterval)
	defer ticker.Stop()
	ctx := stream.Context()
	if err := stream.Send(s.flowStatsProto()); err != nil {
		return err
	}
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			if err := stream.Send(s.flowStatsProto()); err != nil {
				return err
			}
		}
	}
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

func (s *server) authStream(srv any, ss grpc.ServerStream, _ *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
	if s.authorized(ss.Context()) {
		return handler(srv, ss)
	}
	return status.Error(codes.Unauthenticated, "missing or invalid credentials")
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
