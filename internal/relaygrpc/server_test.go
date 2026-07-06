package relaygrpc

import (
	"context"
	"net"
	"testing"

	"github.com/cacggghp/vk-turn-proxy/controlpb"
	"github.com/cacggghp/vk-turn-proxy/internal/peerstore"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
)

func dial(t *testing.T, o Options) controlpb.RelayClient {
	t.Helper()
	if o.Store == nil {
		store, err := peerstore.New("10.66.66.0/24", "wg-test", "", nil)
		if err != nil {
			t.Fatalf("peerstore.New: %v", err)
		}
		o.Store = store
	}
	if o.Version == "" {
		o.Version = "test"
	}
	lis := bufconn.Listen(1 << 20)
	gs := NewServer(o)
	go func() { _ = gs.Serve(lis) }()
	t.Cleanup(gs.Stop)

	conn, err := grpc.NewClient(
		"passthrough:///bufnet",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			return lis.DialContext(ctx)
		}),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return controlpb.NewRelayClient(conn)
}

func TestPeerLifecycle(t *testing.T) {
	client := dial(t, Options{})
	ctx := context.Background()

	peer, err := client.CreatePeer(ctx, &controlpb.CreatePeerRequest{})
	if err != nil {
		t.Fatalf("CreatePeer: %v", err)
	}
	if peer.GetPublicKey() == "" || peer.GetPrivateKey() == "" {
		t.Fatalf("server-generated peer missing keys: %+v", peer)
	}
	if peer.GetServerPublicKey() == "" {
		t.Fatalf("missing server public key")
	}
	if peer.GetAllowedIps() != "10.66.66.2/32" {
		t.Fatalf("allowed_ips = %q, want 10.66.66.2/32", peer.GetAllowedIps())
	}

	status1, err := client.GetStatus(ctx, &controlpb.GetStatusRequest{})
	if err != nil {
		t.Fatalf("GetStatus: %v", err)
	}
	if status1.GetPeerCount() != 1 || status1.GetWgInterface() != "wg-test" {
		t.Fatalf("status = %+v", status1)
	}

	list, err := client.ListPeers(ctx, &controlpb.ListPeersRequest{})
	if err != nil {
		t.Fatalf("ListPeers: %v", err)
	}
	if len(list.GetPeers()) != 1 || list.GetPeers()[0].GetPublicKey() != peer.GetPublicKey() {
		t.Fatalf("ListPeers = %+v", list)
	}

	if _, err := client.DeletePeer(ctx, &controlpb.DeletePeerRequest{PublicKey: peer.GetPublicKey()}); err != nil {
		t.Fatalf("DeletePeer: %v", err)
	}
	if _, err := client.DeletePeer(ctx, &controlpb.DeletePeerRequest{PublicKey: peer.GetPublicKey()}); status.Code(err) != codes.NotFound {
		t.Fatalf("second delete code = %v, want NotFound", status.Code(err))
	}
}

func TestAuthToken(t *testing.T) {
	client := dial(t, Options{Token: "s3cret"})

	if _, err := client.GetStatus(context.Background(), &controlpb.GetStatusRequest{}); status.Code(err) != codes.Unauthenticated {
		t.Fatalf("no-token code = %v, want Unauthenticated", status.Code(err))
	}
	authed := metadata.AppendToOutgoingContext(context.Background(), "authorization", "Bearer s3cret")
	if _, err := client.GetStatus(authed, &controlpb.GetStatusRequest{}); err != nil {
		t.Fatalf("with token: %v", err)
	}
}

type fakeFlows struct{}

func (fakeFlows) Flows() []Flow {
	return []Flow{{
		SessionID: "s1", StreamID: 2, ClientIP: "1.2.3.4", Remote: "1.2.3.4:9000",
		Protocol: "mu", Version: 1, RxBytes: 100, TxBytes: 50, StartedUnix: 111,
	}}
}

func (fakeFlows) FlowStats() FlowStats {
	return FlowStats{
		ActiveStreams: 1, ActiveSessions: 1, TotalSessions: 5,
		AvgSessionLifetimeSeconds: 12.5, ServerRxBytes: 1000,
		StreamsByProtocol: map[string]uint32{"mu": 1},
	}
}

func TestFlows(t *testing.T) {
	client := dial(t, Options{Flows: fakeFlows{}})
	ctx := context.Background()

	flows, err := client.ListFlows(ctx, &controlpb.ListFlowsRequest{})
	if err != nil {
		t.Fatalf("ListFlows: %v", err)
	}
	if len(flows.GetFlows()) != 1 {
		t.Fatalf("flows = %d, want 1", len(flows.GetFlows()))
	}
	f := flows.GetFlows()[0]
	if f.GetSessionId() != "s1" || f.GetClientIp() != "1.2.3.4" || f.GetProtocol() != "mu" || f.GetRxBytes() != 100 {
		t.Fatalf("flow wrong: %+v", f)
	}

	st, err := client.GetFlowStats(ctx, &controlpb.GetFlowStatsRequest{})
	if err != nil {
		t.Fatalf("GetFlowStats: %v", err)
	}
	if st.GetActiveStreams() != 1 || st.GetTotalSessions() != 5 || st.GetAvgSessionLifetimeSeconds() != 12.5 ||
		st.GetStreamsByProtocol()["mu"] != 1 {
		t.Fatalf("flow stats wrong: %+v", st)
	}
}
