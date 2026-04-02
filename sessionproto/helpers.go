package sessionproto

import (
	"encoding/hex"
	"fmt"
	"strings"

	"google.golang.org/protobuf/proto"
)

type Mode string

const (
	ModeMainline Mode = "mainline"
	ModeMux      Mode = "mux"
	ModeAuto     Mode = "auto"

	ProtocolVersion = 1
	SessionIDLen    = 16
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

func BuildProbeHello() ([]byte, error) {
	return proto.Marshal(&ClientHello{
		Version: ProtocolVersion,
		Type:    ClientHelloType_CLIENT_HELLO_TYPE_PROBE,
	})
}

func BuildSessionHello(sessionID []byte, streamID byte) ([]byte, error) {
	if len(sessionID) != SessionIDLen {
		return nil, fmt.Errorf("session ID must be %d bytes", SessionIDLen)
	}
	return proto.Marshal(&ClientHello{
		Version:   ProtocolVersion,
		Type:      ClientHelloType_CLIENT_HELLO_TYPE_SESSION,
		SessionId: append([]byte(nil), sessionID...),
		StreamId:  uint32(streamID),
	})
}

func ParseClientHelloMessage(payload []byte) (*ClientHello, error) {
	var hello ClientHello
	if err := proto.Unmarshal(payload, &hello); err != nil {
		return nil, err
	}
	if hello.GetVersion() == 0 || hello.GetType() == ClientHelloType_CLIENT_HELLO_TYPE_UNSPECIFIED {
		return nil, fmt.Errorf("missing required client hello fields")
	}
	return &hello, nil
}

func ValidateClientHello(hello *ClientHello) error {
	if hello == nil {
		return fmt.Errorf("client hello is nil")
	}
	if hello.GetVersion() != ProtocolVersion {
		return fmt.Errorf("unsupported protocol version: %d", hello.GetVersion())
	}
	switch hello.GetType() {
	case ClientHelloType_CLIENT_HELLO_TYPE_PROBE:
		if len(hello.GetSessionId()) != 0 || hello.GetStreamId() != 0 {
			return fmt.Errorf("probe hello must not contain session data")
		}
		return nil
	case ClientHelloType_CLIENT_HELLO_TYPE_SESSION:
		if len(hello.GetSessionId()) != SessionIDLen {
			return fmt.Errorf("session ID must be %d bytes", SessionIDLen)
		}
		if hello.GetStreamId() > 255 {
			return fmt.Errorf("stream ID out of range: %d", hello.GetStreamId())
		}
		return nil
	default:
		return fmt.Errorf("unsupported client hello type: %s", hello.GetType())
	}
}

func BuildServerHello(muxSupported bool, errorText string) ([]byte, error) {
	return proto.Marshal(&ServerHello{
		Version:      ProtocolVersion,
		MuxSupported: muxSupported,
		Error:        errorText,
	})
}

func ParseServerHelloMessage(payload []byte) (*ServerHello, error) {
	var hello ServerHello
	if err := proto.Unmarshal(payload, &hello); err != nil {
		return nil, err
	}
	if hello.GetVersion() == 0 {
		return nil, fmt.Errorf("missing server hello version")
	}
	return &hello, nil
}
