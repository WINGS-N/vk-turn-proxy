// Package panelclient calls the wingsv-panel Provisioning API during app
// self-enroll: the node forwards the client's panel token and receives the
// client's WireGuard config to hand back over the DTLS PROVISION exchange.
package panelclient

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"

	"github.com/cacggghp/vk-turn-proxy/provisioningpb"
)

// Config is the WireGuard config the panel resolved for a client.
type Config struct {
	PrivateKey      string
	PublicKey       string
	Address         string
	ServerPublicKey string
	AllowedIPs      string
	MTU             uint32
	// ProvisionLocally: the panel asks this node to mint the peer on its own wg
	// interface and re-call to report it (own-wg path), instead of the panel
	// dialing this node's management API back.
	ProvisionLocally bool
}

// Client talks to the panel's Provisioning gRPC endpoint.
type Client struct {
	endpoint    string
	token       string
	creds       credentials.TransportCredentials
	dialContext func(context.Context, string) (net.Conn, error)
}

// Option configures a Client.
type Option func(*Client)

// WithTransportCredentials sets the gRPC transport credentials, overriding the
// system-trust TLS default (used for the pinned-CA path with a self-signed panel).
func WithTransportCredentials(c credentials.TransportCredentials) Option {
	return func(cl *Client) { cl.creds = c }
}

// WithInsecure drops TLS entirely (plaintext h2c). Only for a panel reached over
// a trusted local network or a sidecar; never across the public internet.
func WithInsecure() Option {
	return func(cl *Client) { cl.creds = insecure.NewCredentials() }
}

// WithContextDialer overrides how connections are dialed (used by tests).
func WithContextDialer(d func(context.Context, string) (net.Conn, error)) Option {
	return func(cl *Client) { cl.dialContext = d }
}

// New builds a Client for the panel Provisioning endpoint. token, when set, is
// sent as a bearer credential identifying this node to the panel. The default
// transport is system-trust TLS, so a panel served with a publicly trusted
// (e.g. Let's Encrypt) certificate needs no pin; use WithTransportCredentials
// for a self-signed pinned CA or WithInsecure for plaintext.
func New(endpoint, token string, opts ...Option) *Client {
	c := &Client{endpoint: endpoint, token: token, creds: credentials.NewTLS(&tls.Config{})}
	for _, opt := range opts {
		opt(c)
	}
	return c
}

// ClientUsage is one managed client's traffic-limit state on this node, as the
// panel reports it: byte counters plus a manual-disable flag, keyed by client id
// and wg peer public key.
type ClientUsage struct {
	PublicKey      string
	ClientID       string
	LimitBytes     uint64
	UsedBytes      uint64
	RemainingBytes uint64
	Disabled       bool
}

// GetClientUsage fetches the traffic-limit usage of the capped or disabled
// managed clients holding a peer on nodeID, so the relay can echo used/remaining
// to the app over its heartbeat.
func (c *Client) GetClientUsage(ctx context.Context, nodeID string) ([]ClientUsage, error) {
	dialOpts := []grpc.DialOption{grpc.WithTransportCredentials(c.creds)}
	if c.dialContext != nil {
		dialOpts = append(dialOpts, grpc.WithContextDialer(c.dialContext))
	}
	conn, err := grpc.NewClient(c.endpoint, dialOpts...)
	if err != nil {
		return nil, fmt.Errorf("dial panel %s: %w", c.endpoint, err)
	}
	defer func() { _ = conn.Close() }()

	if c.token != "" {
		ctx = metadata.AppendToOutgoingContext(ctx, "authorization", "Bearer "+c.token)
	}
	resp, err := provisioningpb.NewProvisioningClient(conn).GetClientUsage(ctx, &provisioningpb.GetClientUsageRequest{
		NodeId: nodeID,
	})
	if err != nil {
		return nil, err
	}
	out := make([]ClientUsage, 0, len(resp.GetUsage()))
	for _, u := range resp.GetUsage() {
		out = append(out, ClientUsage{
			PublicKey:      u.GetPublicKey(),
			ClientID:       u.GetClientId(),
			LimitBytes:     u.GetLimitBytes(),
			UsedBytes:      u.GetUsedBytes(),
			RemainingBytes: u.GetRemainingBytes(),
			Disabled:       u.GetDisabled(),
		})
	}
	return out, nil
}

// Resolve verifies the client token with the panel and returns the client's
// WireGuard config for the given node.
func (c *Client) Resolve(ctx context.Context, clientID string, token []byte, hwid, nodeID string) (Config, error) {
	return c.resolve(ctx, &provisioningpb.ResolveClientConfigRequest{
		ClientId: clientID,
		Token:    token,
		Hwid:     hwid,
		NodeId:   nodeID,
	})
}

// ReportPeer records a wg peer this node minted locally (own-wg provision-locally
// path) by re-calling ResolveClientConfig with the wg_* fields, so the panel
// persists it without dialing this node's management API back. Returns the full
// client config (the panel fills in the routing AllowedIPs and MTU).
func (c *Client) ReportPeer(ctx context.Context, clientID string, token []byte, hwid, nodeID, publicKey, privateKey, allowedIPs, serverPublicKey string) (Config, error) {
	return c.resolve(ctx, &provisioningpb.ResolveClientConfigRequest{
		ClientId:          clientID,
		Token:             token,
		Hwid:              hwid,
		NodeId:            nodeID,
		WgPublicKey:       publicKey,
		WgPrivateKey:      privateKey,
		WgAllowedIps:      allowedIPs,
		WgServerPublicKey: serverPublicKey,
	})
}

func (c *Client) resolve(ctx context.Context, req *provisioningpb.ResolveClientConfigRequest) (Config, error) {
	dialOpts := []grpc.DialOption{grpc.WithTransportCredentials(c.creds)}
	if c.dialContext != nil {
		dialOpts = append(dialOpts, grpc.WithContextDialer(c.dialContext))
	}
	conn, err := grpc.NewClient(c.endpoint, dialOpts...)
	if err != nil {
		return Config{}, fmt.Errorf("dial panel %s: %w", c.endpoint, err)
	}
	defer func() { _ = conn.Close() }()

	if c.token != "" {
		ctx = metadata.AppendToOutgoingContext(ctx, "authorization", "Bearer "+c.token)
	}
	resp, err := provisioningpb.NewProvisioningClient(conn).ResolveClientConfig(ctx, req)
	if err != nil {
		return Config{}, err
	}
	wg := resp.GetWg()
	return Config{
		PrivateKey:       wg.GetPrivateKey(),
		PublicKey:        wg.GetPublicKey(),
		Address:          wg.GetAddress(),
		ServerPublicKey:  wg.GetServerPublicKey(),
		AllowedIPs:       wg.GetAllowedIps(),
		MTU:              wg.GetMtu(),
		ProvisionLocally: resp.GetProvisionLocally(),
	}, nil
}
