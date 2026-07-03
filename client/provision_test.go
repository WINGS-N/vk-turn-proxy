package main

import (
	"net"
	"testing"

	"github.com/cacggghp/vk-turn-proxy/sessionproto"
)

func fakeProvisionNode(t *testing.T, conn net.Conn, resp *sessionproto.ProvisionResponse) {
	t.Helper()
	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		_ = conn.Close()
		return
	}
	hello, err := sessionproto.ParseClientHelloMessage(buf[:n])
	if err != nil || hello.GetType() != sessionproto.ClientHelloType_CLIENT_HELLO_TYPE_PROVISION {
		_ = conn.Close()
		return
	}
	req := hello.GetProvision()
	if req.GetClientId() != "c1" || string(req.GetToken()) != "tok" || req.GetHwid() != "hw" {
		resp = &sessionproto.ProvisionResponse{Error: "bad request"}
	}
	payload, _ := sessionproto.MarshalProvisionResponse(resp)
	_, _ = conn.Write(payload)
	_ = conn.Close()
}

func TestRequestProvisionSuccess(t *testing.T) {
	client, server := net.Pipe()
	go fakeProvisionNode(t, server, &sessionproto.ProvisionResponse{
		Wg: &sessionproto.WireguardConfig{PrivateKey: "priv", PublicKey: "pub", Address: "10.66.66.2/32", Mtu: 1280},
	})

	resp, err := RequestProvision(client, "c1", []byte("tok"), "hw", 9000)
	if err != nil {
		t.Fatalf("RequestProvision: %v", err)
	}
	if resp.GetWg().GetPrivateKey() != "priv" || resp.GetWg().GetAddress() != "10.66.66.2/32" || resp.GetWg().GetMtu() != 1280 {
		t.Fatalf("wg config wrong: %+v", resp.GetWg())
	}
}

func TestRequestProvisionNodeError(t *testing.T) {
	client, server := net.Pipe()
	go fakeProvisionNode(t, server, &sessionproto.ProvisionResponse{Error: "invalid token"})

	if _, err := RequestProvision(client, "c1", []byte("tok"), "hw", 9000); err == nil {
		t.Fatal("expected an error when the node returns an error")
	}
}
