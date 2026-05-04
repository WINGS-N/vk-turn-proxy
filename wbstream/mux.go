package wbstream

import (
	"fmt"
)

// SessionIDLen is the fixed length of session identifiers carried in mux frames.
// Matches sessionproto.SessionIDLen so we can reuse the same identifier on both
// transports.
const SessionIDLen = 16

const (
	// muxFrameVersion is bumped if the wire format changes incompatibly.
	muxFrameVersion uint8 = 2

	// MuxHeaderSize covers version + session id + stream id.
	// Payload length is implicit from len(raw)-MuxHeaderSize because LiveKit
	// DataPackets are length-delimited at the SCTP layer.
	MuxHeaderSize = 1 + SessionIDLen + 1
)

// MuxFrame describes one logical packet exchanged between two wbstream peers.
type MuxFrame struct {
	SessionID [SessionIDLen]byte
	StreamID  byte
	Payload   []byte
}

// Encode serialises a frame into its on-the-wire representation.
func (f *MuxFrame) Encode() []byte {
	out := make([]byte, MuxHeaderSize+len(f.Payload))
	out[0] = muxFrameVersion
	copy(out[1:1+SessionIDLen], f.SessionID[:])
	out[1+SessionIDLen] = f.StreamID
	copy(out[MuxHeaderSize:], f.Payload)
	return out
}

// DecodeMuxFrame parses raw bytes back into a MuxFrame.
func DecodeMuxFrame(raw []byte) (*MuxFrame, error) {
	if len(raw) < MuxHeaderSize {
		return nil, fmt.Errorf("mux frame too short: %d bytes", len(raw))
	}
	if raw[0] != muxFrameVersion {
		return nil, fmt.Errorf("unsupported mux frame version: %d", raw[0])
	}
	frame := &MuxFrame{StreamID: raw[1+SessionIDLen]}
	copy(frame.SessionID[:], raw[1:1+SessionIDLen])
	frame.Payload = append([]byte(nil), raw[MuxHeaderSize:]...)
	return frame, nil
}
