package controlpath

import (
	"fmt"
	"strings"
	"time"

	"github.com/cacggghp/vk-turn-proxy/sessionproto"
)

const (
	ProviderTurn = "turn"

	PathTurnDTLS = "turn-dtls"
)

type HeartbeatMeta struct {
	SessionMode string
	ControlPath string
	Provider    string
	Transport   sessionproto.TransportMode
	ActiveFlows uint32
}

func BuildHeartbeat(meta HeartbeatMeta) ([]byte, error) {
	return sessionproto.MarshalHeartbeat(&sessionproto.Heartbeat{
		Version:       1,
		WallClockMs:   time.Now().UnixMilli(),
		ActiveStreams: meta.ActiveFlows,
		Online:        true,
		SessionMode:   strings.TrimSpace(meta.SessionMode),
		ControlPath:   strings.TrimSpace(meta.ControlPath),
		Provider:      strings.TrimSpace(meta.Provider),
		Transport:     meta.Transport,
	})
}

func DescribeHeartbeat(heartbeat *sessionproto.Heartbeat) string {
	if heartbeat == nil {
		return "<nil>"
	}
	parts := []string{
		fmt.Sprintf("online=%t", heartbeat.GetOnline()),
		fmt.Sprintf("version=%d", heartbeat.GetVersion()),
	}
	if sessionMode := strings.TrimSpace(heartbeat.GetSessionMode()); sessionMode != "" {
		parts = append(parts, fmt.Sprintf("session_mode=%s", sessionMode))
	}
	if controlPath := strings.TrimSpace(heartbeat.GetControlPath()); controlPath != "" {
		parts = append(parts, fmt.Sprintf("control_path=%s", controlPath))
	}
	if provider := strings.TrimSpace(heartbeat.GetProvider()); provider != "" {
		parts = append(parts, fmt.Sprintf("provider=%s", provider))
	}
	if transport := heartbeat.GetTransport(); transport != sessionproto.TransportMode_TRANSPORT_MODE_UNSPECIFIED {
		parts = append(parts, fmt.Sprintf("transport=%s", transport))
	}
	if activeStreams := heartbeat.GetActiveStreams(); activeStreams > 0 {
		parts = append(parts, fmt.Sprintf("active_streams=%d", activeStreams))
	}
	return strings.Join(parts, " ")
}
