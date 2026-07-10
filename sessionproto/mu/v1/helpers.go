package v1

import (
	"fmt"
	"sync/atomic"

	"github.com/cacggghp/vk-turn-proxy/sessionproto"
)

const ProtocolVersion uint32 = 1

// sessionClientID is the managed client's panel id, announced in every mu SESSION
// hello so the node can attribute the session for traffic-limit reporting. It is
// a per-process singleton (one libvkturn serves one client), set once from the
// app's Configure and empty for a non-managed client.
var sessionClientID atomic.Pointer[string]

// SetSessionClientID records the managed client id to announce in SESSION hellos.
// An empty id clears it (non-managed client).
func SetSessionClientID(id string) {
	if id == "" {
		sessionClientID.Store(nil)
		return
	}
	v := id
	sessionClientID.Store(&v)
}

func currentSessionClientID() string {
	if p := sessionClientID.Load(); p != nil {
		return *p
	}
	return ""
}

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

// BuildProvisionHello builds a CLIENT_HELLO_TYPE_PROVISION hello carrying the
// panel client token: the node verifies it with the panel and returns the
// client's WireGuard config.
func BuildProvisionHello(clientID string, token []byte, hwid string, localPort uint32) ([]byte, error) {
	return sessionproto.MarshalClientHello(&sessionproto.ClientHello{
		Version: ProtocolVersion,
		Type:    sessionproto.ClientHelloType_CLIENT_HELLO_TYPE_PROVISION,
		Provision: &sessionproto.ProvisionRequest{
			ClientId:  clientID,
			Token:     append([]byte(nil), token...),
			Hwid:      hwid,
			LocalPort: localPort,
		},
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
	return BuildSessionHelloWithWrap(
		sessionID,
		streamID,
		requestedTransport,
		supportedTransports,
		nil,
		nil,
	)
}

// BuildSessionHelloWithWrap extends BuildSessionHelloWithTransport with WRAP
// per-packet obfuscation negotiation fields. Pass nil/empty slices to disable.
func BuildSessionHelloWithWrap(
	sessionID []byte,
	streamID byte,
	requestedTransport sessionproto.TransportMode,
	supportedTransports []sessionproto.TransportMode,
	supportedWrapCiphers []sessionproto.WrapCipher,
	wrapKeyProposal []byte,
) ([]byte, error) {
	if len(sessionID) != sessionproto.SessionIDLen {
		return nil, fmt.Errorf("session ID must be %d bytes", sessionproto.SessionIDLen)
	}
	var keyCopy []byte
	if len(wrapKeyProposal) > 0 {
		keyCopy = append([]byte(nil), wrapKeyProposal...)
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
		SupportedWrapCiphers: append([]sessionproto.WrapCipher(nil), supportedWrapCiphers...),
		WrapKeyProposal:      keyCopy,
		ClientId:             currentSessionClientID(),
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
	return BuildServerHelloWithWrap(
		muSupported,
		errorText,
		controlHeartbeatSupported,
		selectedTransport,
		supportedTransports,
		supportedTcpFlavors,
		selectedTcpFlavor,
		sessionproto.WrapCipher_WRAP_CIPHER_UNSPECIFIED,
	)
}

// BuildServerHelloWithWrap extends BuildServerHelloWithTcpFlavor with the
// final WRAP cipher decision negotiated against the client.
func BuildServerHelloWithWrap(
	muSupported bool,
	errorText string,
	controlHeartbeatSupported bool,
	selectedTransport sessionproto.TransportMode,
	supportedTransports []sessionproto.TransportMode,
	supportedTcpFlavors []sessionproto.TcpTransportFlavor,
	selectedTcpFlavor sessionproto.TcpTransportFlavor,
	selectedWrapCipher sessionproto.WrapCipher,
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
		SelectedWrapCipher:  selectedWrapCipher,
	})
}
