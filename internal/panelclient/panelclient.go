// Package panelclient calls the wingsv-panel Provisioning API during app
// self-enroll: the node forwards the client's panel token and receives the
// client's WireGuard config to hand back over the DTLS PROVISION exchange.
package panelclient

import (
	"context"
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

// WithTransportCredentials sets the gRPC transport credentials (pinned-CA mTLS
// to the panel). The default is insecure.
func WithTransportCredentials(c credentials.TransportCredentials) Option {
	return func(cl *Client) { cl.creds = c }
}

// WithContextDialer overrides how connections are dialed (used by tests).
func WithContextDialer(d func(context.Context, string) (net.Conn, error)) Option {
	return func(cl *Client) { cl.dialContext = d }
}

// New builds a Client for the panel Provisioning endpoint. token, when set, is
// sent as a bearer credential identifying this node to the panel.
func New(endpoint, token string, opts ...Option) *Client {
	c := &Client{endpoint: endpoint, token: token, creds: insecure.NewCredentials()}
	for _, opt := range opts {
		opt(c)
	}
	return c
}

// Resolve verifies the client token with the panel and returns the client's
// WireGuard config for the given node.
func (c *Client) Resolve(ctx context.Context, clientID string, token []byte, hwid, nodeID string) (Config, error) {
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
	resp, err := provisioningpb.NewProvisioningClient(conn).ResolveClientConfig(ctx, &provisioningpb.ResolveClientConfigRequest{
		ClientId: clientID,
		Token:    token,
		Hwid:     hwid,
		NodeId:   nodeID,
	})
	if err != nil {
		return Config{}, err
	}
	wg := resp.GetWg()
	return Config{
		PrivateKey:      wg.GetPrivateKey(),
		PublicKey:       wg.GetPublicKey(),
		Address:         wg.GetAddress(),
		ServerPublicKey: wg.GetServerPublicKey(),
		AllowedIPs:      wg.GetAllowedIps(),
		MTU:             wg.GetMtu(),
	}, nil
}
