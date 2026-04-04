package v2

import (
	"fmt"

	"github.com/cacggghp/vk-turn-proxy/sessionproto"
)

const ProtocolVersion uint32 = 2

func BuildProbeHello() ([]byte, error) {
	return sessionproto.MarshalClientHello(&sessionproto.ClientHello{
		Version: ProtocolVersion,
		Type:    sessionproto.ClientHelloType_CLIENT_HELLO_TYPE_PROBE,
	})
}

func BuildSessionHello(sessionID []byte, streamID byte) ([]byte, error) {
	if len(sessionID) != sessionproto.SessionIDLen {
		return nil, fmt.Errorf("session ID must be %d bytes", sessionproto.SessionIDLen)
	}
	return sessionproto.MarshalClientHello(&sessionproto.ClientHello{
		Version:   ProtocolVersion,
		Type:      sessionproto.ClientHelloType_CLIENT_HELLO_TYPE_SESSION,
		SessionId: append([]byte(nil), sessionID...),
		StreamId:  uint32(streamID),
	})
}

func ValidateClientHello(hello *sessionproto.ClientHello) error {
	return sessionproto.ValidateHelloShape(hello, ProtocolVersion)
}

func BuildServerHello(muxSupported bool, errorText string) ([]byte, error) {
	return sessionproto.MarshalServerHello(&sessionproto.ServerHello{
		Version:      ProtocolVersion,
		MuxSupported: muxSupported,
		Error:        errorText,
	})
}
