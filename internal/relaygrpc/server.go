// Package relaygrpc serves the Relay management API (proto/control.proto) that
// the wingsv-panel calls to inspect a vk-turn-proxy node and manage its tunnel
// peers. It is a thin adapter over internal/peerstore.
package relaygrpc

import (
	"bufio"
	"context"
	"crypto/subtle"
	"log"
	"net"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cacggghp/vk-turn-proxy/controlpb"
	"github.com/cacggghp/vk-turn-proxy/internal/peerstore"
	"github.com/cacggghp/vk-turn-proxy/internal/tokenaead"
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

	ready       func() bool
	bootID      string
	wrapCipher  string
	wrapCiphers []string
	started     time.Time

	// reload re-reads what can be re-read while traffic keeps flowing, and
	// configVersion counts the times it succeeded, so a caller can see its change
	// land instead of assuming it did
	reload        func(context.Context) (applied []string, restartRequired []string, err error)
	configVersion atomic.Uint64

	// seenDerivation remembers which peers have already been logged, keyed by
	// remote address, so the migration line appears once and not per RPC
	seenDerivation sync.Map
}

// hasAESNI reports whether AES is hardware accelerated here. Without it the
// software AES path is far slower than ChaCha20, which is what makes this worth
// reporting to a scheduler at all
func hasAESNI() bool {
	f, err := os.Open("/proc/cpuinfo")
	if err != nil {
		return false
	}
	defer func() { _ = f.Close() }()
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if !strings.HasPrefix(line, "flags") && !strings.HasPrefix(line, "Features") {
			continue
		}
		for _, field := range strings.Fields(line) {
			if field == "aes" {
				return true
			}
		}
	}
	return false
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
	// Ready reports whether the relay can actually carry traffic. A supervisor
	// that only sees the process running marks a node healthy while every client
	// still fails
	Ready func() bool
	// BootID changes per process start so a consumer can tell a restart from a
	// counter moving backwards
	BootID string
	// WrapCipher and SupportedWrapCiphers let a scheduler pick the cipher that
	// suits this machine
	WrapCipher           string
	SupportedWrapCiphers []string
	// Reload re-reads whatever the relay can pick up without dropping traffic.
	// Left nil, Reload still answers - it just reports that everything needs a
	// restart, which is the truth for a relay that cannot re-read anything.
	Reload func(context.Context) (applied []string, restartRequired []string, err error)
}

// NewServer builds a grpc.Server serving the Relay service. When Token is set,
// callers must present it as a bearer token; a verified client certificate
// (mTLS) is always accepted.
// flowStatsStreamInterval is how often StreamFlowStats pushes a snapshot. One
// second gives the panel responsive rx/tx rates without flooding the link.
const flowStatsStreamInterval = time.Second

func NewServer(o Options) *grpc.Server {
	s := &server{
		store: o.Store, version: o.Version, sessions: o.Sessions, token: o.Token,
		flows: o.Flows, listen: o.Listen, ready: o.Ready, bootID: o.BootID,
		wrapCipher: o.WrapCipher, wrapCiphers: o.SupportedWrapCiphers, reload: o.Reload,
		started: time.Now(),
	}
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
	ready := true
	if s.ready != nil {
		ready = s.ready()
	}
	return &controlpb.Status{
		Version:              s.version,
		WgInterface:          s.store.Interface(),
		PeerCount:            uint32(s.store.Count()),
		ActiveSessions:       active,
		ListenEndpoint:       s.listen,
		Ready:                ready,
		UptimeSeconds:        uint64(time.Since(s.started).Seconds()),
		BootId:               s.bootID,
		AesNi:                hasAESNI(),
		WrapCipher:           s.wrapCipher,
		SupportedWrapCiphers: s.wrapCiphers,
		ConfigVersion:        s.configVersion.Load(),
	}, nil
}

// Reload re-reads what it can and says plainly what it could not.
//
// The listen address and the transport key are bound when the process starts, so
// they are reported as needing a restart rather than quietly ignored: a relay
// that answers "done" and keeps serving the old value is worse than one that
// admits it cannot.
func (s *server) Reload(ctx context.Context, _ *controlpb.ReloadRequest) (*controlpb.ReloadResponse, error) {
	if s.reload == nil {
		return &controlpb.ReloadResponse{
			RestartRequired: []string{"listen", "grpc-token", "wrap-cipher"},
			ConfigVersion:   s.configVersion.Load(),
		}, nil
	}
	applied, restart, err := s.reload(ctx)
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}
	version := s.configVersion.Load()
	if len(applied) > 0 {
		version = s.configVersion.Add(1)
	}
	return &controlpb.ReloadResponse{
		Applied:         applied,
		RestartRequired: restart,
		ConfigVersion:   version,
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

// noteDerivation logs, once per peer, which key derivation it turned up with.
// Accepting both is a migration, and a migration nobody can see the end of never
// ends: this is how an operator knows when the sha256 path can be dropped.
func (s *server) noteDerivation(ctx context.Context) {
	pr, ok := peer.FromContext(ctx)
	if !ok || pr.AuthInfo == nil {
		return
	}
	variant, ok := tokenaead.NegotiatedVariant(pr.AuthInfo)
	if !ok {
		return
	}
	// Keyed by host, not by the full address: the panel opens a fresh connection
	// per poll, so an ephemeral port in the key would log this every few seconds
	// for the lifetime of the process
	host := peerHost(pr.Addr.String())
	if _, seen := s.seenDerivation.LoadOrStore(host, variant); seen {
		return
	}
	log.Printf("relay grpc: peer %s uses %s key derivation", host, variant)
}

func peerHost(addr string) string {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return addr
	}
	return host
}

func (s *server) authUnary(ctx context.Context, req any, _ *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
	s.noteDerivation(ctx)
	if s.authorized(ctx) {
		return handler(ctx, req)
	}
	return nil, status.Error(codes.Unauthenticated, "missing or invalid credentials")
}

func (s *server) authStream(srv any, ss grpc.ServerStream, _ *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
	s.noteDerivation(ss.Context())
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
