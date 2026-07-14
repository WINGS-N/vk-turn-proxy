package main

import (
	"context"
	"net"
	"testing"

	"github.com/cacggghp/vk-turn-proxy/internal/panelclient"
	"github.com/cacggghp/vk-turn-proxy/sessionproto"
)

type fakeResolver struct {
	cfg         panelclient.Config
	err         error
	gotClientID string
	gotNodeID   string
	gotToken    []byte
}

func (f *fakeResolver) Resolve(_ context.Context, clientID string, token []byte, _, nodeID string) (panelclient.Config, error) {
	f.gotClientID = clientID
	f.gotNodeID = nodeID
	f.gotToken = token
	return f.cfg, f.err
}

func (f *fakeResolver) ReportPeer(_ context.Context, _ string, _ []byte, _, _, _, _, _, _ string) (panelclient.Config, error) {
	return f.cfg, f.err
}

func runProvision(t *testing.T, hello *sessionproto.ClientHello) *sessionproto.ProvisionResponse {
	t.Helper()
	server, client := net.Pipe()
	go func() {
		_ = handleProvision(server, hello)
		_ = server.Close()
	}()
	buf := make([]byte, 4096)
	n, err := client.Read(buf)
	_ = client.Close()
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	resp, perr := sessionproto.ParseProvisionResponseMessage(buf[:n])
	if perr != nil {
		t.Fatalf("parse response: %v", perr)
	}
	return resp
}

func provisionHello() *sessionproto.ClientHello {
	return &sessionproto.ClientHello{
		Type: sessionproto.ClientHelloType_CLIENT_HELLO_TYPE_PROVISION,
		Provision: &sessionproto.ProvisionRequest{
			ClientId: "c1", Token: []byte("tok"), Hwid: "hw", LocalPort: 9000,
		},
	}
}

func TestProvisionSuccess(t *testing.T) {
	fake := &fakeResolver{cfg: panelclient.Config{
		PrivateKey: "priv", PublicKey: "pub", Address: "10.66.66.2/32",
		ServerPublicKey: "spub", AllowedIPs: "0.0.0.0/0", MTU: 1280,
	}}
	SetProvisionResolver(fake, "n1", nil)
	t.Cleanup(func() { SetProvisionResolver(nil, "", nil) })

	resp := runProvision(t, provisionHello())
	if resp.GetError() != "" {
		t.Fatalf("unexpected error: %q", resp.GetError())
	}
	wg := resp.GetWg()
	if wg.GetPrivateKey() != "priv" || wg.GetAddress() != "10.66.66.2/32" || wg.GetMtu() != 1280 {
		t.Fatalf("wg config wrong: %+v", wg)
	}
	if fake.gotClientID != "c1" || fake.gotNodeID != "n1" || string(fake.gotToken) != "tok" {
		t.Fatalf("resolver got client=%q node=%q token=%q", fake.gotClientID, fake.gotNodeID, fake.gotToken)
	}
}

func TestProvisionDisabled(t *testing.T) {
	SetProvisionResolver(nil, "", nil)
	resp := runProvision(t, provisionHello())
	if resp.GetError() == "" {
		t.Fatal("expected an error when provisioning is disabled")
	}
	if resp.GetWg() != nil {
		t.Fatalf("wg should be nil when disabled, got %+v", resp.GetWg())
	}
}

func TestProvisionMissingRequest(t *testing.T) {
	SetProvisionResolver(&fakeResolver{}, "n1", nil)
	t.Cleanup(func() { SetProvisionResolver(nil, "", nil) })
	hello := &sessionproto.ClientHello{Type: sessionproto.ClientHelloType_CLIENT_HELLO_TYPE_PROVISION}
	resp := runProvision(t, hello)
	if resp.GetError() == "" {
		t.Fatal("expected an error for a missing provision request")
	}
}
