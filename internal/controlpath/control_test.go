package controlpath

import (
	"testing"

	"github.com/cacggghp/vk-turn-proxy/sessionproto"
)

func TestHeartbeatRoundTrip(t *testing.T) {
	meta := HeartbeatMeta{
		SessionMode: "mainline",
		ControlPath: PathTurnDTLS,
		Provider:    ProviderTurn,
		Transport:   sessionproto.TransportMode_TRANSPORT_MODE_DATAGRAM,
		ActiveFlows: 3,
	}

	payload, err := BuildHeartbeat(meta)
	if err != nil {
		t.Fatalf("BuildHeartbeat() error = %v", err)
	}

	heartbeat, err := sessionproto.ParseHeartbeatMessage(payload)
	if err != nil {
		t.Fatalf("ParseHeartbeatMessage() error = %v", err)
	}
	if got := heartbeat.GetSessionMode(); got != "mainline" {
		t.Fatalf("session mode = %q", got)
	}
	if got := heartbeat.GetControlPath(); got != PathTurnDTLS {
		t.Fatalf("control path = %q", got)
	}
	if got := heartbeat.GetProvider(); got != ProviderTurn {
		t.Fatalf("provider = %q", got)
	}
	if got := heartbeat.GetTransport(); got != sessionproto.TransportMode_TRANSPORT_MODE_DATAGRAM {
		t.Fatalf("transport = %s", got)
	}
	if got := heartbeat.GetActiveStreams(); got != 3 {
		t.Fatalf("active streams = %d", got)
	}
}
