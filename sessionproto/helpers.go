package sessionproto

import (
	"encoding/hex"
	"fmt"
	"strings"
)

type Mode string

const (
	ModeMainline Mode = "mainline"
	ModeMux      Mode = "mux"
	ModeAuto     Mode = "auto"

	SessionIDLen = 16
)

func ParseMode(raw string) (Mode, error) {
	switch Mode(strings.TrimSpace(strings.ToLower(raw))) {
	case "", ModeAuto:
		return ModeAuto, nil
	case ModeMainline, "legacy":
		return ModeMainline, nil
	case ModeMux:
		return ModeMux, nil
	default:
		return "", fmt.Errorf("unsupported session mode: %s", raw)
	}
}

func ParseSessionIDHex(raw string) ([]byte, error) {
	decoded, err := hex.DecodeString(strings.TrimSpace(raw))
	if err != nil {
		return nil, err
	}
	if len(decoded) != SessionIDLen {
		return nil, fmt.Errorf("session ID must be %d bytes", SessionIDLen)
	}
	return decoded, nil
}

func ParseClientHelloMessage(payload []byte) (*ClientHello, error) {
	var hello ClientHello
	if err := unmarshalProto(payload, &hello); err != nil {
		return nil, err
	}
	if hello.GetVersion() == 0 || hello.GetType() == ClientHelloType_CLIENT_HELLO_TYPE_UNSPECIFIED {
		return nil, fmt.Errorf("missing required client hello fields")
	}
	return &hello, nil
}

func ParseServerHelloMessage(payload []byte) (*ServerHello, error) {
	var hello ServerHello
	if err := unmarshalProto(payload, &hello); err != nil {
		return nil, err
	}
	if hello.GetVersion() == 0 {
		return nil, fmt.Errorf("missing server hello version")
	}
	return &hello, nil
}

func ParseHeartbeatMessage(payload []byte) (*Heartbeat, error) {
	var heartbeat Heartbeat
	if err := unmarshalProto(payload, &heartbeat); err != nil {
		return nil, err
	}
	if heartbeat.GetVersion() == 0 {
		return nil, fmt.Errorf("missing heartbeat version")
	}
	return &heartbeat, nil
}

func NormalizeSupportedTransports(transports []TransportMode) []TransportMode {
	normalized := make([]TransportMode, 0, len(transports))
	seen := make(map[TransportMode]struct{}, len(transports))
	for _, transport := range transports {
		if transport == TransportMode_TRANSPORT_MODE_UNSPECIFIED {
			continue
		}
		if _, exists := seen[transport]; exists {
			continue
		}
		seen[transport] = struct{}{}
		normalized = append(normalized, transport)
	}
	return normalized
}

func HasSupportedTransport(transports []TransportMode, target TransportMode) bool {
	for _, transport := range NormalizeSupportedTransports(transports) {
		if transport == target {
			return true
		}
	}
	return false
}
