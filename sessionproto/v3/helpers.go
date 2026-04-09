package v3

import (
	"fmt"

	"github.com/cacggghp/vk-turn-proxy/sessionproto"
)

const ProtocolVersion uint32 = 3

func BuildProbeHello() ([]byte, error) {
	return BuildProbeHelloWithTransport(
		sessionproto.TransportMode_TRANSPORT_MODE_DATAGRAM,
		[]sessionproto.TransportMode{sessionproto.TransportMode_TRANSPORT_MODE_DATAGRAM},
	)
}

func BuildProbeHelloWithTransport(requestedTransport sessionproto.TransportMode, supportedTransports []sessionproto.TransportMode) ([]byte, error) {
	return sessionproto.MarshalClientHello(&sessionproto.ClientHello{
		Version:            ProtocolVersion,
		Type:               sessionproto.ClientHelloType_CLIENT_HELLO_TYPE_PROBE,
		RequestedTransport: requestedTransport,
		SupportedTransports: sessionproto.NormalizeSupportedTransports(
			supportedTransports,
		),
	})
}

func BuildSessionHello(sessionID []byte, streamID byte) ([]byte, error) {
	return BuildSessionHelloWithTransport(
		sessionID,
		streamID,
		sessionproto.TransportMode_TRANSPORT_MODE_DATAGRAM,
		[]sessionproto.TransportMode{sessionproto.TransportMode_TRANSPORT_MODE_DATAGRAM},
	)
}

func BuildSessionHelloWithTransport(
	sessionID []byte,
	streamID byte,
	requestedTransport sessionproto.TransportMode,
	supportedTransports []sessionproto.TransportMode,
) ([]byte, error) {
	if len(sessionID) != sessionproto.SessionIDLen {
		return nil, fmt.Errorf("session ID must be %d bytes", sessionproto.SessionIDLen)
	}
	return sessionproto.MarshalClientHello(&sessionproto.ClientHello{
		Version:            ProtocolVersion,
		Type:               sessionproto.ClientHelloType_CLIENT_HELLO_TYPE_SESSION,
		SessionId:          append([]byte(nil), sessionID...),
		StreamId:           uint32(streamID),
		RequestedTransport: requestedTransport,
		SupportedTransports: sessionproto.NormalizeSupportedTransports(
			supportedTransports,
		),
	})
}

func ValidateClientHello(hello *sessionproto.ClientHello) error {
	return sessionproto.ValidateHelloShape(hello, ProtocolVersion)
}

func BuildServerHello(muxSupported bool, errorText string, controlHeartbeatSupported bool) ([]byte, error) {
	return BuildServerHelloWithTransport(
		muxSupported,
		errorText,
		controlHeartbeatSupported,
		sessionproto.TransportMode_TRANSPORT_MODE_DATAGRAM,
		[]sessionproto.TransportMode{sessionproto.TransportMode_TRANSPORT_MODE_DATAGRAM},
	)
}

func BuildServerHelloWithTransport(
	muxSupported bool,
	errorText string,
	controlHeartbeatSupported bool,
	selectedTransport sessionproto.TransportMode,
	supportedTransports []sessionproto.TransportMode,
) ([]byte, error) {
	return sessionproto.MarshalServerHello(&sessionproto.ServerHello{
		Version:                   ProtocolVersion,
		MuxSupported:              muxSupported,
		Error:                     errorText,
		ControlHeartbeatSupported: controlHeartbeatSupported,
		SelectedTransport:         selectedTransport,
		SupportedTransports: sessionproto.NormalizeSupportedTransports(
			supportedTransports,
		),
	})
}
