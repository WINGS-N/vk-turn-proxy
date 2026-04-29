package main

import (
	"encoding/hex"
	"fmt"
	"log"
	"net"
	"time"

	"github.com/cacggghp/vk-turn-proxy/internal/controlpath"
	"github.com/cacggghp/vk-turn-proxy/sessionproto"
	sessionmuv1 "github.com/cacggghp/vk-turn-proxy/sessionproto/mu/v1"
)

func describeClientHello(hello *sessionproto.ClientHello) string {
	if hello == nil {
		return "<nil>"
	}
	sessionID := ""
	if len(hello.GetSessionId()) > 0 {
		sessionID = hex.EncodeToString(hello.GetSessionId())
	}
	return fmt.Sprintf(
		"version=%d type=%s stream=%d session=%s requested_transport=%s",
		hello.GetVersion(),
		hello.GetType(),
		hello.GetStreamId(),
		sessionID,
		hello.GetRequestedTransport(),
	)
}

func writeServerHelloForVersion(
	conn net.Conn,
	version uint32,
	muSupported bool,
	errorText string,
	controlHeartbeatSupported bool,
	selectedTransport sessionproto.TransportMode,
	supportedTransports []sessionproto.TransportMode,
) error {
	return writeServerHelloForVersionWithTcpFlavor(
		conn,
		version,
		muSupported,
		errorText,
		controlHeartbeatSupported,
		selectedTransport,
		supportedTransports,
		nil,
		sessionproto.TcpTransportFlavor_TCP_TRANSPORT_FLAVOR_UNSPECIFIED,
	)
}

func writeServerHelloForVersionWithTcpFlavor(
	conn net.Conn,
	version uint32,
	muSupported bool,
	errorText string,
	controlHeartbeatSupported bool,
	selectedTransport sessionproto.TransportMode,
	supportedTransports []sessionproto.TransportMode,
	supportedTcpFlavors []sessionproto.TcpTransportFlavor,
	selectedTcpFlavor sessionproto.TcpTransportFlavor,
) error {
	payload, err := buildServerHelloForVersionWithTcpFlavor(
		version,
		muSupported,
		errorText,
		controlHeartbeatSupported,
		selectedTransport,
		supportedTransports,
		supportedTcpFlavors,
		selectedTcpFlavor,
	)
	if err != nil {
		return err
	}
	if err := conn.SetWriteDeadline(time.Now().Add(5 * time.Second)); err != nil {
		return err
	}
	if _, err := conn.Write(payload); err != nil {
		return err
	}
	return conn.SetWriteDeadline(time.Time{})
}

func buildServerHelloForVersion(
	version uint32,
	muSupported bool,
	errorText string,
	controlHeartbeatSupported bool,
	selectedTransport sessionproto.TransportMode,
	supportedTransports []sessionproto.TransportMode,
) ([]byte, error) {
	return buildServerHelloForVersionWithTcpFlavor(
		version,
		muSupported,
		errorText,
		controlHeartbeatSupported,
		selectedTransport,
		supportedTransports,
		nil,
		sessionproto.TcpTransportFlavor_TCP_TRANSPORT_FLAVOR_UNSPECIFIED,
	)
}

func buildServerHelloForVersionWithTcpFlavor(
	version uint32,
	muSupported bool,
	errorText string,
	controlHeartbeatSupported bool,
	selectedTransport sessionproto.TransportMode,
	supportedTransports []sessionproto.TransportMode,
	supportedTcpFlavors []sessionproto.TcpTransportFlavor,
	selectedTcpFlavor sessionproto.TcpTransportFlavor,
) ([]byte, error) {
	switch version {
	case sessionmuv1.ProtocolVersion:
		return sessionmuv1.BuildServerHelloWithTcpFlavor(
			muSupported,
			errorText,
			controlHeartbeatSupported,
			selectedTransport,
			supportedTransports,
			supportedTcpFlavors,
			selectedTcpFlavor,
		)
	default:
		return nil, fmt.Errorf("unsupported protocol version: %d", version)
	}
}

func validateClientHelloForVersion(hello *sessionproto.ClientHello) error {
	switch hello.GetVersion() {
	case sessionmuv1.ProtocolVersion:
		return sessionmuv1.ValidateClientHello(hello)
	default:
		return fmt.Errorf("unsupported protocol version: %d", hello.GetVersion())
	}
}

func handleMainlineControlPacket(
	conn net.Conn,
	payload []byte,
	mode sessionproto.Mode,
	backends transportBackends,
) (bool, error) {
	probePayload, ok := sessionproto.ParseControlProbeRequest(payload)
	if !ok {
		return false, nil
	}
	log.Printf("protobuf mainline control probe from %s", conn.RemoteAddr())

	hello, err := sessionproto.ParseClientHelloMessage(probePayload)
	if err != nil {
		log.Printf("protobuf mainline control probe parse failed from %s: %v", conn.RemoteAddr(), err)
		return true, nil
	}
	log.Printf("protobuf mainline control hello from %s: %s", conn.RemoteAddr(), describeClientHello(hello))
	if err := validateClientHelloForVersion(hello); err != nil {
		log.Printf("protobuf mainline control reject from %s: %v", conn.RemoteAddr(), err)
		responsePayload, buildErr := buildServerHelloForVersion(
			hello.GetVersion(),
			false,
			err.Error(),
			true,
			sessionproto.TransportMode_TRANSPORT_MODE_DATAGRAM,
			supportedTransportsForHello(mode, backends, hello),
		)
		if buildErr != nil {
			return true, nil
		}
		response := sessionproto.BuildControlProbeResponse(responsePayload)
		if writeErr := writeRawPacket(conn, response); writeErr != nil {
			return true, writeErr
		}
		return true, nil
	}
	if hello.GetType() != sessionproto.ClientHelloType_CLIENT_HELLO_TYPE_PROBE {
		log.Printf("protobuf mainline control ignore from %s: unsupported type %s", conn.RemoteAddr(), hello.GetType())
		return true, nil
	}

	muSupported := mode != sessionproto.ModeMainline
	errorText := ""
	if !muSupported {
		errorText = "server session mode is mainline"
	}
	selectedTransport := sessionproto.TransportMode_TRANSPORT_MODE_DATAGRAM
	supportedTransports := supportedTransportsForHello(mode, backends, hello)
	log.Printf(
		"protobuf mainline control response to %s: version=%d mu_supported=%t selected_transport=%s error=%q",
		conn.RemoteAddr(),
		hello.GetVersion(),
		muSupported,
		selectedTransport,
		errorText,
	)
	responsePayload, err := buildServerHelloForVersion(
		hello.GetVersion(),
		muSupported,
		errorText,
		true,
		selectedTransport,
		supportedTransports,
	)
	if err != nil {
		return true, err
	}
	response := sessionproto.BuildControlProbeResponse(responsePayload)
	return true, writeRawPacket(conn, response)
}

func writeRawPacket(conn net.Conn, payload []byte) error {
	if err := conn.SetWriteDeadline(time.Now().Add(5 * time.Second)); err != nil {
		return err
	}
	if _, err := conn.Write(payload); err != nil {
		return err
	}
	return conn.SetWriteDeadline(time.Time{})
}

func buildServerHeartbeatPayload(meta controlpath.HeartbeatMeta) ([]byte, error) {
	return controlpath.BuildHeartbeat(meta)
}

func handleControlHeartbeatPacket(conn net.Conn, payload []byte, streamKey string, meta controlpath.HeartbeatMeta) (bool, error) {
	heartbeatPayload, ok := sessionproto.ParseControlHeartbeatRequest(payload)
	if !ok {
		return false, nil
	}
	heartbeat, err := sessionproto.ParseHeartbeatMessage(heartbeatPayload)
	if err != nil {
		log.Printf("protobuf heartbeat parse failed from %s: %v", conn.RemoteAddr(), err)
		return true, nil
	}
	if serverUI != nil {
		serverUI.noteStreamHeartbeat(streamKey)
	}
	log.Printf(
		"protobuf heartbeat from %s: %s",
		conn.RemoteAddr(),
		controlpath.DescribeHeartbeat(heartbeat),
	)
	responsePayload, err := buildServerHeartbeatPayload(meta)
	if err != nil {
		return true, err
	}
	response := sessionproto.BuildControlHeartbeatResponse(responsePayload)
	return true, writeRawPacket(conn, response)
}
