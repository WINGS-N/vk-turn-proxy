package wbstream

import (
	"context"
	"errors"
	"fmt"
	"log"
	"sync/atomic"

	lksdk "github.com/livekit/server-sdk-go/v2"
)

// MultiRoomPeer drives N LiveKit rooms in parallel, each with its own Peer
// instance. Outbound MuxFrames are distributed round-robin across rooms;
// inbound frames from any room are funneled through one SetFrameHandler.
//
// Each room is a separate SFU session, so per-room bandwidth caps don't
// stack — N rooms = N× ceiling. Trade-off: N× signalling cost on startup
// (RegisterGuest + CreateRoom + JoinRoom + GetRoomToken per room) and N×
// ROOM_EXCHANGE deliveries to inform the peer server which rooms to join.
type MultiRoomPeer struct {
	peers []*Peer

	rrSendIdx atomic.Uint64
	closed    atomic.Bool
}

// NewMultiRoom creates one Peer per supplied roomID. Empty entries (including
// "" or "any") cause the SFU to mint a fresh room when that peer connects;
// the resolved IDs are then available via RoomIDs() after Connect.
//
// Every peer shares the same E2EKey — all rooms of one logical session use
// one wrapping key so the server can decode regardless of which room
// delivered the frame.
func NewMultiRoom(cfg PeerConfig, roomIDs []string) (*MultiRoomPeer, error) {
	if len(roomIDs) == 0 {
		return nil, errors.New("multi-room peer requires at least one room")
	}
	if len(roomIDs) > 16 {
		return nil, fmt.Errorf("too many rooms: %d (max 16)", len(roomIDs))
	}
	mp := &MultiRoomPeer{peers: make([]*Peer, 0, len(roomIDs))}
	for i, roomID := range roomIDs {
		peerCfg := cfg
		peerCfg.RoomID = roomID
		if peerCfg.DisplayName != "" && len(roomIDs) > 1 {
			peerCfg.DisplayName = fmt.Sprintf("%s-%d", peerCfg.DisplayName, i+1)
		}
		peer, err := New(peerCfg)
		if err != nil {
			_ = mp.Close()
			return nil, fmt.Errorf("init peer[%d]: %w", i, err)
		}
		mp.peers = append(mp.peers, peer)
	}
	return mp, nil
}

func (m *MultiRoomPeer) SetFrameHandler(handler func(*MuxFrame, lksdk.DataReceiveParams)) {
	for _, p := range m.peers {
		p.SetFrameHandler(handler)
	}
}

// Connect joins each peer to its own room. Failure on any single peer aborts
// the rest.
func (m *MultiRoomPeer) Connect(ctx context.Context) error {
	if m.closed.Load() {
		return errors.New("multi-room peer closed")
	}
	for i, peer := range m.peers {
		if err := peer.Connect(ctx); err != nil {
			return fmt.Errorf("connect peer[%d] room=%q: %w", i, peer.cfg.RoomID, err)
		}
	}
	rooms := m.RoomIDs()
	log.Printf("wbstream multi-room peer joined %d rooms: %v", len(m.peers), rooms)
	return nil
}

// RoomIDs returns the list of resolved room IDs in peer order. Useful for
// reporting the IDs back to the operator (or to the server-side ROOM_EXCHANGE
// caller) when peers were started with empty/"any" requests.
func (m *MultiRoomPeer) RoomIDs() []string {
	out := make([]string, 0, len(m.peers))
	for _, p := range m.peers {
		out = append(out, p.RoomID())
	}
	return out
}

// Send picks a peer round-robin and enqueues the frame on it.
func (m *MultiRoomPeer) Send(frame *MuxFrame) error {
	if m.closed.Load() {
		return errors.New("multi-room peer closed")
	}
	if len(m.peers) == 0 {
		return errors.New("multi-room peer has no peers")
	}
	idx := int(m.rrSendIdx.Add(1)-1) % len(m.peers)
	return m.peers[idx].Send(frame)
}

// Close disconnects every underlying peer.
func (m *MultiRoomPeer) Close() error {
	if !m.closed.CompareAndSwap(false, true) {
		return nil
	}
	var firstErr error
	for _, p := range m.peers {
		if err := p.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}
