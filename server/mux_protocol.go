package main

import (
	"encoding/hex"
	"fmt"
	"log"
	"net"
	"time"

	"github.com/cacggghp/vk-turn-proxy/sessionproto"
	sessionv1 "github.com/cacggghp/vk-turn-proxy/sessionproto/v1"
	sessionv2 "github.com/cacggghp/vk-turn-proxy/sessionproto/v2"
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
		"version=%d type=%s stream=%d session=%s",
		hello.GetVersion(),
		hello.GetType(),
		hello.GetStreamId(),
		sessionID,
	)
}

func writeServerHelloForVersion(
	conn net.Conn,
	version uint32,
	muxSupported bool,
	errorText string,
	controlHeartbeatSupported bool,
) error {
	payload, err := buildServerHelloForVersion(version, muxSupported, errorText, controlHeartbeatSupported)
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
	muxSupported bool,
	errorText string,
	controlHeartbeatSupported bool,
) ([]byte, error) {
	switch version {
	case sessionv1.ProtocolVersion:
		return sessionv1.BuildServerHello(muxSupported, errorText, controlHeartbeatSupported)
	case sessionv2.ProtocolVersion:
		return sessionv2.BuildServerHello(muxSupported, errorText, controlHeartbeatSupported)
	default:
		return nil, fmt.Errorf("unsupported protocol version: %d", version)
	}
}

func validateClientHelloForVersion(hello *sessionproto.ClientHello) error {
	switch hello.GetVersion() {
	case sessionv1.ProtocolVersion:
		return sessionv1.ValidateClientHello(hello)
	case sessionv2.ProtocolVersion:
		return sessionv2.ValidateClientHello(hello)
	default:
		return fmt.Errorf("unsupported protocol version: %d", hello.GetVersion())
	}
}

func handleMainlineControlPacket(conn net.Conn, payload []byte, mode sessionproto.Mode) (bool, error) {
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
		responsePayload, buildErr := buildServerHelloForVersion(hello.GetVersion(), false, err.Error(), true)
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

	muxSupported := mode != sessionproto.ModeMainline
	errorText := ""
	if !muxSupported {
		errorText = "server session mode is mainline"
	}
	log.Printf(
		"protobuf mainline control response to %s: version=%d mux_supported=%t error=%q",
		conn.RemoteAddr(),
		hello.GetVersion(),
		muxSupported,
		errorText,
	)
	responsePayload, err := buildServerHelloForVersion(hello.GetVersion(), muxSupported, errorText, true)
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

func buildServerHeartbeatPayload(activeStreams uint32) ([]byte, error) {
	return sessionproto.MarshalHeartbeat(&sessionproto.Heartbeat{
		Version:       1,
		WallClockMs:   time.Now().UnixMilli(),
		ActiveStreams: activeStreams,
		Online:        true,
	})
}

func handleControlHeartbeatPacket(conn net.Conn, payload []byte, streamKey string, activeStreams uint32) (bool, error) {
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
		"protobuf heartbeat from %s: online=%t active_streams=%d version=%d wg_fp=%q",
		conn.RemoteAddr(),
		heartbeat.GetOnline(),
		heartbeat.GetActiveStreams(),
		heartbeat.GetVersion(),
		heartbeat.GetWireguardPublicKeyFingerprint(),
	)
	responsePayload, err := buildServerHeartbeatPayload(activeStreams)
	if err != nil {
		return true, err
	}
	response := sessionproto.BuildControlHeartbeatResponse(responsePayload)
	return true, writeRawPacket(conn, response)
}
