package panelclient

import (
	"context"
	"net"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/test/bufconn"

	"github.com/cacggghp/vk-turn-proxy/provisioningpb"
)

type stubProvisioning struct {
	provisioningpb.UnimplementedProvisioningServer
	gotToken    string
	gotClientID string
	gotNodeID   string
}

func (s *stubProvisioning) ResolveClientConfig(ctx context.Context, req *provisioningpb.ResolveClientConfigRequest) (*provisioningpb.ResolveClientConfigResponse, error) {
	if md, ok := metadata.FromIncomingContext(ctx); ok {
		if vals := md.Get("authorization"); len(vals) > 0 {
			s.gotToken = vals[0]
		}
	}
	s.gotClientID = req.GetClientId()
	s.gotNodeID = req.GetNodeId()
	return &provisioningpb.ResolveClientConfigResponse{
		Wg: &provisioningpb.WireguardConfig{
			PrivateKey: "priv", PublicKey: "pub", Address: "10.66.66.2/32",
			ServerPublicKey: "spub", AllowedIps: "0.0.0.0/0", Mtu: 1280,
		},
	}, nil
}

func TestResolveMapsResponse(t *testing.T) {
	lis := bufconn.Listen(1 << 20)
	gs := grpc.NewServer()
	stub := &stubProvisioning{}
	provisioningpb.RegisterProvisioningServer(gs, stub)
	go func() { _ = gs.Serve(lis) }()
	t.Cleanup(gs.Stop)

	c := New("passthrough:///bufnet", "node-token", WithInsecure(), WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
		return lis.DialContext(ctx)
	}))
	cfg, err := c.Resolve(context.Background(), "c1", []byte("tok"), "hw", "n1")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if cfg.PrivateKey != "priv" || cfg.Address != "10.66.66.2/32" || cfg.AllowedIPs != "0.0.0.0/0" || cfg.MTU != 1280 {
		t.Fatalf("mapping wrong: %+v", cfg)
	}
	if stub.gotToken != "Bearer node-token" {
		t.Fatalf("token = %q, want 'Bearer node-token'", stub.gotToken)
	}
	if stub.gotClientID != "c1" || stub.gotNodeID != "n1" {
		t.Fatalf("forwarded ids wrong: client=%q node=%q", stub.gotClientID, stub.gotNodeID)
	}
}
