package sessionproto

import (
	"bytes"
	"fmt"
)

var controlPacketMagic = []byte{0x57, 0x56, 0x4d, 0x58, 0x01}

const (
	controlPacketKindProbeRequest  byte = 1
	controlPacketKindProbeResponse byte = 2
	controlPacketKindHeartbeatReq  byte = 3
	controlPacketKindHeartbeatResp byte = 4
	controlPacketKindSessionReq    byte = 5
	controlPacketKindSessionResp   byte = 6
)

func BuildControlProbeRequest(payload []byte) []byte {
	return buildControlPacket(controlPacketKindProbeRequest, payload)
}

func BuildControlProbeResponse(payload []byte) []byte {
	return buildControlPacket(controlPacketKindProbeResponse, payload)
}

func ParseControlProbeRequest(payload []byte) ([]byte, bool) {
	return parseControlPacket(payload, controlPacketKindProbeRequest)
}

func ParseControlProbeResponse(payload []byte) ([]byte, bool) {
	return parseControlPacket(payload, controlPacketKindProbeResponse)
}

func BuildControlHeartbeatRequest(payload []byte) []byte {
	return buildControlPacket(controlPacketKindHeartbeatReq, payload)
}

func BuildControlHeartbeatResponse(payload []byte) []byte {
	return buildControlPacket(controlPacketKindHeartbeatResp, payload)
}

func ParseControlHeartbeatRequest(payload []byte) ([]byte, bool) {
	return parseControlPacket(payload, controlPacketKindHeartbeatReq)
}

func ParseControlHeartbeatResponse(payload []byte) ([]byte, bool) {
	return parseControlPacket(payload, controlPacketKindHeartbeatResp)
}

func BuildControlSessionRequest(payload []byte) []byte {
	return buildControlPacket(controlPacketKindSessionReq, payload)
}

func BuildControlSessionResponse(payload []byte) []byte {
	return buildControlPacket(controlPacketKindSessionResp, payload)
}

func ParseControlSessionRequest(payload []byte) ([]byte, bool) {
	return parseControlPacket(payload, controlPacketKindSessionReq)
}

func ParseControlSessionResponse(payload []byte) ([]byte, bool) {
	return parseControlPacket(payload, controlPacketKindSessionResp)
}

func buildControlPacket(kind byte, payload []byte) []byte {
	packet := make([]byte, 0, len(controlPacketMagic)+1+len(payload))
	packet = append(packet, controlPacketMagic...)
	packet = append(packet, kind)
	packet = append(packet, payload...)
	return packet
}

func parseControlPacket(payload []byte, expectedKind byte) ([]byte, bool) {
	if len(payload) < len(controlPacketMagic)+1 {
		return nil, false
	}
	if !bytes.Equal(payload[:len(controlPacketMagic)], controlPacketMagic) {
		return nil, false
	}
	if payload[len(controlPacketMagic)] != expectedKind {
		return nil, false
	}
	return payload[len(controlPacketMagic)+1:], true
}

func ValidateHelloShape(hello *ClientHello, expectedVersion uint32) error {
	if hello == nil {
		return fmt.Errorf("client hello is nil")
	}
	if hello.GetVersion() != expectedVersion {
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
