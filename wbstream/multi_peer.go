package wbstream

import (
	"context"
	"errors"
	"fmt"
	"log"
	"sync/atomic"

	lksdk "github.com/livekit/server-sdk-go/v2"
)

// MultiPeer drives N LiveKit identities joined to the same room. Outbound
// MuxFrames are distributed round-robin across peers; inbound frames from any
// peer are funneled through one SetFrameHandler callback.
//
// Server-side response addressing is NOT yet wired — every server response
// reaches all N identities (broadcast). The downstream WG/MuxFrame consumer
// must tolerate duplicate delivery; WireGuard's replay window already does.
type MultiPeer struct {
	count int
	peers []*Peer

	rrSendIdx atomic.Uint64
	closed    atomic.Bool
}

// NewMulti creates count Peer instances. If count <= 1 it returns a single
// underlying Peer (callers can use this without branching for the singleton
// case).
func NewMulti(cfg PeerConfig, count int) (*MultiPeer, error) {
	if count <= 0 {
		count = 1
	}
	if count > 16 {
		return nil, fmt.Errorf("multi-peer count too high: %d (max 16)", count)
	}
	mp := &MultiPeer{count: count, peers: make([]*Peer, 0, count)}
	for i := 0; i < count; i++ {
		peerCfg := cfg
		if peerCfg.DisplayName != "" && count > 1 {
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

// SetFrameHandler installs the same callback on every underlying peer.
func (m *MultiPeer) SetFrameHandler(handler func(*MuxFrame, lksdk.DataReceiveParams)) {
	for _, p := range m.peers {
		p.SetFrameHandler(handler)
	}
}

// Connect joins all peers to the same room. Peer 0 acquires (or creates) the
// room first; the resolved RoomID is then forced onto the remaining peers so
// they land in the same SFU room with their own LiveKit identities.
func (m *MultiPeer) Connect(ctx context.Context) error {
	if m.closed.Load() {
		return errors.New("multi-peer closed")
	}
	if len(m.peers) == 0 {
		return errors.New("multi-peer has no peers")
	}
	first := m.peers[0]
	if err := first.Connect(ctx); err != nil {
		return fmt.Errorf("connect peer[0]: %w", err)
	}
	roomID := first.RoomID()
	for i := 1; i < len(m.peers); i++ {
		m.peers[i].cfg.RoomID = roomID
		if err := m.peers[i].Connect(ctx); err != nil {
			return fmt.Errorf("connect peer[%d]: %w", i, err)
		}
	}
	identities := make([]string, 0, len(m.peers))
	for _, peer := range m.peers {
		if id := peer.LocalIdentity(); id != "" {
			identities = append(identities, id)
		}
	}
	for _, peer := range m.peers {
		peer.SetSiblings(identities)
	}
	log.Printf("wbstream multi-peer joined room=%s with %d identities", roomID, len(m.peers))
	return nil
}

// RoomID returns the shared room ID joined by all identities.
func (m *MultiPeer) RoomID() string {
	if len(m.peers) == 0 {
		return ""
	}
	return m.peers[0].RoomID()
}

// Send picks a peer round-robin and enqueues the frame on it. Each peer has
// its own send queue so a saturated/slow LiveKit path doesn't block siblings.
func (m *MultiPeer) Send(frame *MuxFrame) error {
	if m.closed.Load() {
		return errors.New("multi-peer closed")
	}
	if len(m.peers) == 0 {
		return errors.New("multi-peer has no peers")
	}
	idx := int(m.rrSendIdx.Add(1)-1) % len(m.peers)
	return m.peers[idx].Send(frame)
}

// Close disconnects every underlying peer.
func (m *MultiPeer) Close() error {
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
