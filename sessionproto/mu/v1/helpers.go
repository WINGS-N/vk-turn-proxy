package v1

import (
	"fmt"

	"github.com/cacggghp/vk-turn-proxy/sessionproto"
)

const ProtocolVersion uint32 = 1

func BuildProbeHello() ([]byte, error) {
	return BuildProbeHelloWithTransport(
		sessionproto.TransportMode_TRANSPORT_MODE_DATAGRAM,
		[]sessionproto.TransportMode{sessionproto.TransportMode_TRANSPORT_MODE_DATAGRAM},
	)
}

func BuildProbeHelloWithTransport(requestedTransport sessionproto.TransportMode, supportedTransports []sessionproto.TransportMode) ([]byte, error) {
	return BuildProbeHelloWithTcpFlavors(
		requestedTransport,
		supportedTransports,
		nil,
		sessionproto.TcpTransportFlavor_TCP_TRANSPORT_FLAVOR_UNSPECIFIED,
	)
}

func BuildProbeHelloWithTcpFlavors(
	requestedTransport sessionproto.TransportMode,
	supportedTransports []sessionproto.TransportMode,
	supportedTcpFlavors []sessionproto.TcpTransportFlavor,
	preferredTcpFlavor sessionproto.TcpTransportFlavor,
) ([]byte, error) {
	return sessionproto.MarshalClientHello(&sessionproto.ClientHello{
		Version:            ProtocolVersion,
		Type:               sessionproto.ClientHelloType_CLIENT_HELLO_TYPE_PROBE,
		RequestedTransport: requestedTransport,
		SupportedTransports: sessionproto.NormalizeSupportedTransports(
			supportedTransports,
		),
		SupportedTcpFlavors: sessionproto.NormalizeSupportedTcpFlavors(supportedTcpFlavors),
		PreferredTcpFlavor:  preferredTcpFlavor,
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

// BuildRoomExchangeHello marshals a CLIENT_HELLO_TYPE_ROOM_EXCHANGE message
// carrying a RoomDataExchange payload. Used for short-lived TURN-handshake
// sessions where the client only conveys a room identifier and exits.
func BuildRoomExchangeHello(exchange *sessionproto.RoomDataExchange) ([]byte, error) {
	if exchange == nil {
		return nil, fmt.Errorf("room exchange payload is required")
	}
	return sessionproto.MarshalClientHello(&sessionproto.ClientHello{
		Version:      ProtocolVersion,
		Type:         sessionproto.ClientHelloType_CLIENT_HELLO_TYPE_ROOM_EXCHANGE,
		RoomExchange: exchange,
	})
}

func BuildServerHello(muSupported bool, errorText string, controlHeartbeatSupported bool) ([]byte, error) {
	return BuildServerHelloWithTransport(
		muSupported,
		errorText,
		controlHeartbeatSupported,
		sessionproto.TransportMode_TRANSPORT_MODE_DATAGRAM,
		[]sessionproto.TransportMode{sessionproto.TransportMode_TRANSPORT_MODE_DATAGRAM},
	)
}

func BuildServerHelloWithTransport(
	muSupported bool,
	errorText string,
	controlHeartbeatSupported bool,
	selectedTransport sessionproto.TransportMode,
	supportedTransports []sessionproto.TransportMode,
) ([]byte, error) {
	return BuildServerHelloWithTcpFlavor(
		muSupported,
		errorText,
		controlHeartbeatSupported,
		selectedTransport,
		supportedTransports,
		nil,
		sessionproto.TcpTransportFlavor_TCP_TRANSPORT_FLAVOR_UNSPECIFIED,
	)
}

func BuildServerHelloWithTcpFlavor(
	muSupported bool,
	errorText string,
	controlHeartbeatSupported bool,
	selectedTransport sessionproto.TransportMode,
	supportedTransports []sessionproto.TransportMode,
	supportedTcpFlavors []sessionproto.TcpTransportFlavor,
	selectedTcpFlavor sessionproto.TcpTransportFlavor,
) ([]byte, error) {
	return sessionproto.MarshalServerHello(&sessionproto.ServerHello{
		Version:                   ProtocolVersion,
		MuSupported:               muSupported,
		Error:                     errorText,
		ControlHeartbeatSupported: controlHeartbeatSupported,
		SelectedTransport:         selectedTransport,
		SupportedTransports: sessionproto.NormalizeSupportedTransports(
			supportedTransports,
		),
		SupportedTcpFlavors: sessionproto.NormalizeSupportedTcpFlavors(supportedTcpFlavors),
		SelectedTcpFlavor:   selectedTcpFlavor,
	})
}
