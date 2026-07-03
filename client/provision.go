package main

import (
	"context"
	"fmt"
	"net"
	"sync/atomic"
	"time"

	"github.com/cacggghp/vk-turn-proxy/appcontrolpb"
	"github.com/cacggghp/vk-turn-proxy/sessionproto"
	sessionmuv1 "github.com/cacggghp/vk-turn-proxy/sessionproto/mu/v1"
)

// provisionExchange is a one-shot request parked for the next DTLS worker to run
// on its fresh connection, plus the channel the worker reports the result on.
type provisionExchange struct {
	clientID  string
	token     []byte
	hwid      string
	localPort uint32
	result    chan provisionResult
}

type provisionResult struct {
	resp *sessionproto.ProvisionResponse
	err  error
}

// pendingProvision holds at most one in-flight enrollment. The AppControl
// Provision handler publishes it; the first DTLS worker to bring up a connection
// claims it (CAS to nil) and runs the exchange there, so PROVISION rides the exact
// same TURN allocation + DTLS dial as a session, differing only in the hello.
var pendingProvision atomic.Pointer[provisionExchange]

// runPendingProvisionOnConn is called by a DTLS worker right after its connection
// is up, before it sends the session hello. If an enrollment is parked it claims
// and runs it on this connection and returns true. The node treats PROVISION as a
// non-terminal prefix hello and keeps the connection open, so the worker then
// proceeds with its normal session hello on the SAME connection - no reconnect.
func runPendingProvisionOnConn(dtlsConn net.Conn) bool {
	ex := pendingProvision.Load()
	if ex == nil {
		return false
	}
	if !pendingProvision.CompareAndSwap(ex, nil) {
		return false
	}
	resp, err := RequestProvision(dtlsConn, ex.clientID, ex.token, ex.hwid, ex.localPort)
	ex.result <- provisionResult{resp: resp, err: err}
	return true
}

// provisionViaWorker is the AppControl ProvisionFunc. It parks the enrollment for
// the next worker connection and waits for the result, then maps the minted config
// onto the AppControl wire type. It refuses to run two enrollments at once.
func provisionViaWorker(
	ctx context.Context,
	clientID string,
	token []byte,
	hwid string,
	localPort uint32,
) (*appcontrolpb.WireguardConfig, error) {
	ex := &provisionExchange{
		clientID:  clientID,
		token:     token,
		hwid:      hwid,
		localPort: localPort,
		result:    make(chan provisionResult, 1),
	}
	if !pendingProvision.CompareAndSwap(nil, ex) {
		return nil, fmt.Errorf("another provisioning is already in flight")
	}
	defer pendingProvision.CompareAndSwap(ex, nil)
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-time.After(45 * time.Second):
		return nil, fmt.Errorf("provisioning timed out waiting for a relay connection")
	case res := <-ex.result:
		if res.err != nil {
			return nil, res.err
		}
		wg := res.resp.GetWg()
		if wg == nil {
			return nil, fmt.Errorf("provisioning returned no config")
		}
		return &appcontrolpb.WireguardConfig{
			PrivateKey:      wg.GetPrivateKey(),
			PublicKey:       wg.GetPublicKey(),
			Address:         wg.GetAddress(),
			ServerPublicKey: wg.GetServerPublicKey(),
			AllowedIps:      wg.GetAllowedIps(),
			Mtu:             wg.GetMtu(),
		}, nil
	}
}

// RequestProvision sends a PROVISION hello over an established control-channel
// conn (a DTLS connection through VK TURN) and returns the WireGuard config the
// node minted for the client. The hello is wrapped in the same control-session
// frame as a mu SessionHello (the server dispatches PROVISION vs SESSION by the
// inner ClientHello type); the node forwards the panel client token to the panel
// for verification. The app drives this once to enroll a managed profile.
func RequestProvision(
	conn net.Conn,
	clientID string,
	token []byte,
	hwid string,
	localPort uint32,
) (*sessionproto.ProvisionResponse, error) {
	hello, err := sessionmuv1.BuildProvisionHello(clientID, token, hwid, localPort)
	if err != nil {
		return nil, err
	}
	packet := sessionproto.BuildControlSessionRequest(hello)
	if err := conn.SetWriteDeadline(time.Now().Add(5 * time.Second)); err != nil {
		return nil, err
	}
	if _, err := conn.Write(packet); err != nil {
		return nil, fmt.Errorf("provision: write hello: %w", err)
	}
	_ = conn.SetWriteDeadline(time.Time{})
	_ = conn.SetReadDeadline(time.Now().Add(15 * time.Second))
	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		return nil, fmt.Errorf("provision: read response: %w", err)
	}
	_ = conn.SetReadDeadline(time.Time{})
	resp, err := sessionproto.ParseProvisionResponseMessage(buf[:n])
	if err != nil {
		return nil, fmt.Errorf("provision: parse response: %w", err)
	}
	if resp.GetError() != "" {
		return nil, fmt.Errorf("provision: node error: %s", resp.GetError())
	}
	return resp, nil
}
