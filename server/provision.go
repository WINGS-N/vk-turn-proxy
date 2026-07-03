package main

import (
	"context"
	"log"
	"net"
	"sync/atomic"
	"time"

	"github.com/cacggghp/vk-turn-proxy/internal/panelclient"
	"github.com/cacggghp/vk-turn-proxy/sessionproto"
)

// provisionResolver verifies a client token with the panel and returns the
// client's WireGuard config. panelclient.Client satisfies it.
type provisionResolver interface {
	Resolve(ctx context.Context, clientID string, token []byte, hwid, nodeID string) (panelclient.Config, error)
}

type provisionConfig struct {
	resolver provisionResolver
	nodeID   string
}

var provisionState atomic.Pointer[provisionConfig]

// SetProvisionResolver enables the DTLS PROVISION path. Pass nil to disable it.
func SetProvisionResolver(resolver provisionResolver, nodeID string) {
	if resolver == nil {
		provisionState.Store(nil)
		return
	}
	provisionState.Store(&provisionConfig{resolver: resolver, nodeID: nodeID})
}

// handleProvision serves a CLIENT_HELLO_TYPE_PROVISION hello: it forwards the
// client_id + token to the panel for verification and writes back the resolved
// WireGuard config (or an error) as a single marshaled ProvisionResponse record.
func handleProvision(conn net.Conn, hello *sessionproto.ClientHello) error {
	cfg := provisionState.Load()
	if cfg == nil {
		return writeProvisionError(conn, "provisioning is not enabled on this node")
	}
	req := hello.GetProvision()
	if req == nil || req.GetClientId() == "" || len(req.GetToken()) == 0 {
		return writeProvisionError(conn, "missing provision request")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	wg, err := cfg.resolver.Resolve(ctx, req.GetClientId(), req.GetToken(), req.GetHwid(), cfg.nodeID)
	if err != nil {
		log.Printf("provision for client %s failed: %v", req.GetClientId(), err)
		return writeProvisionError(conn, "provision failed")
	}
	return writeProvisionResponse(conn, &sessionproto.ProvisionResponse{
		Wg: &sessionproto.WireguardConfig{
			PrivateKey:      wg.PrivateKey,
			PublicKey:       wg.PublicKey,
			Address:         wg.Address,
			ServerPublicKey: wg.ServerPublicKey,
			AllowedIps:      wg.AllowedIPs,
			Mtu:             wg.MTU,
		},
	})
}

func writeProvisionError(conn net.Conn, message string) error {
	return writeProvisionResponse(conn, &sessionproto.ProvisionResponse{Error: message})
}

func writeProvisionResponse(conn net.Conn, resp *sessionproto.ProvisionResponse) error {
	payload, err := sessionproto.MarshalProvisionResponse(resp)
	if err != nil {
		return err
	}
	_, err = conn.Write(payload)
	return err
}
