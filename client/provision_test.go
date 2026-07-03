package main

import (
	"context"
	"net"
	"testing"
	"time"

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
	// The client wraps the hello in a control-session frame exactly like a mu
	// SessionHello; unwrap it the same way the real server dispatch does.
	sessionPayload, ok := sessionproto.ParseControlSessionRequest(buf[:n])
	if !ok {
		_ = conn.Close()
		return
	}
	hello, err := sessionproto.ParseClientHelloMessage(sessionPayload)
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

// TestProvisionViaWorker drives the full AppControl backend: the handler parks an
// enrollment and a worker claims it on its connection, mirroring how a live DTLS
// worker picks up pendingProvision right after connecting.
func TestProvisionViaWorker(t *testing.T) {
	pendingProvision.Store(nil)
	t.Cleanup(func() { pendingProvision.Store(nil) })

	client, server := net.Pipe()
	go fakeProvisionNode(t, server, &sessionproto.ProvisionResponse{
		Wg: &sessionproto.WireguardConfig{PrivateKey: "priv", ServerPublicKey: "spub", Address: "10.66.66.2/32", Mtu: 1280},
	})

	done := make(chan struct{})
	go func() {
		defer close(done)
		// Poll like a worker bringing up successive connections.
		for i := 0; i < 200; i++ {
			if runPendingProvisionOnConn(client) {
				return
			}
			time.Sleep(2 * time.Millisecond)
		}
	}()

	wg, err := provisionViaWorker(context.Background(), "c1", []byte("tok"), "hw", 9000)
	if err != nil {
		t.Fatalf("provisionViaWorker: %v", err)
	}
	<-done
	if wg.GetPrivateKey() != "priv" || wg.GetServerPublicKey() != "spub" || wg.GetAddress() != "10.66.66.2/32" || wg.GetMtu() != 1280 {
		t.Fatalf("mapped wg config wrong: %+v", wg)
	}
}

func TestProvisionViaWorkerRejectsConcurrent(t *testing.T) {
	pendingProvision.Store(nil)
	t.Cleanup(func() { pendingProvision.Store(nil) })

	pendingProvision.Store(&provisionExchange{result: make(chan provisionResult, 1)})
	if _, err := provisionViaWorker(context.Background(), "c1", []byte("tok"), "hw", 9000); err == nil {
		t.Fatal("expected a rejection while another enrollment is in flight")
	}
}
