package main

import (
	"fmt"
	"net"
	"time"

	"github.com/cacggghp/vk-turn-proxy/sessionproto"
	sessionmuv1 "github.com/cacggghp/vk-turn-proxy/sessionproto/mu/v1"
)

// RequestProvision sends a PROVISION hello over an established control-channel
// conn (a DTLS connection through VK TURN) and returns the WireGuard config the
// node minted for the client. The node forwards the panel client token to the
// panel for verification; the app drives this once to enroll a managed profile.
func RequestProvision(conn net.Conn, clientID string, token []byte, hwid string, localPort uint32) (*sessionproto.ProvisionResponse, error) {
	hello, err := sessionmuv1.BuildProvisionHello(clientID, token, hwid, localPort)
	if err != nil {
		return nil, err
	}
	if _, err := conn.Write(hello); err != nil {
		return nil, fmt.Errorf("provision: write hello: %w", err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(15 * time.Second))
	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		return nil, fmt.Errorf("provision: read response: %w", err)
	}
	resp, err := sessionproto.ParseProvisionResponseMessage(buf[:n])
	if err != nil {
		return nil, fmt.Errorf("provision: parse response: %w", err)
	}
	if resp.GetError() != "" {
		return nil, fmt.Errorf("provision: node error: %s", resp.GetError())
	}
	return resp, nil
}
