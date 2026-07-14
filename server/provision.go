package main

import (
	"context"
	"log"
	"net"
	"sync/atomic"
	"time"

	"github.com/cacggghp/vk-turn-proxy/internal/panelclient"
	"github.com/cacggghp/vk-turn-proxy/internal/peerstore"
	"github.com/cacggghp/vk-turn-proxy/sessionproto"
)

// provisionResolver verifies a client token with the panel and returns the
// client's WireGuard config. panelclient.Client satisfies it. ReportPeer records
// a peer this node minted locally (own-wg provision-locally path).
type provisionResolver interface {
	Resolve(ctx context.Context, clientID string, token []byte, hwid, nodeID string) (panelclient.Config, error)
	ReportPeer(ctx context.Context, clientID string, token []byte, hwid, nodeID, publicKey, privateKey, allowedIPs, serverPublicKey string) (panelclient.Config, error)
}

type provisionConfig struct {
	resolver provisionResolver
	nodeID   string
	store    *peerstore.Store
}

var provisionState atomic.Pointer[provisionConfig]

// SetProvisionResolver enables the DTLS PROVISION path. store is this node's wg
// peerstore, used to mint peers locally on the own-wg provision path. Pass a nil
// resolver to disable provisioning.
func SetProvisionResolver(resolver provisionResolver, nodeID string, store *peerstore.Store) {
	if resolver == nil {
		provisionState.Store(nil)
		return
	}
	provisionState.Store(&provisionConfig{resolver: resolver, nodeID: nodeID, store: store})
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
	// Own-wg provision-locally: the panel asked us to mint the peer on our own wg
	// interface (avoids the panel dialing our management API back re-entrantly).
	// Create it locally, then report it so the panel records it and returns the
	// full client config (routing AllowedIPs + MTU). Roll back on record failure.
	if wg.ProvisionLocally {
		if cfg.store == nil {
			log.Printf("provision for client %s: provision-locally but no peerstore", req.GetClientId())
			return writeProvisionError(conn, "provision failed")
		}
		created, cErr := cfg.store.Create("", "")
		if cErr != nil {
			log.Printf("provision for client %s: local peer create: %v", req.GetClientId(), cErr)
			return writeProvisionError(conn, "provision failed")
		}
		wg, err = cfg.resolver.ReportPeer(ctx, req.GetClientId(), req.GetToken(), req.GetHwid(), cfg.nodeID,
			created.Peer.PublicKey, created.PrivateKey, created.Peer.AllowedIPs, cfg.store.ServerPublicKey())
		if err != nil {
			_ = cfg.store.Delete(created.Peer.PublicKey)
			log.Printf("provision for client %s: report peer: %v", req.GetClientId(), err)
			return writeProvisionError(conn, "provision failed")
		}
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
