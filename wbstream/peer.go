package wbstream

import (
	"context"
	"errors"
	"fmt"
	"log"
	"sync"
	"sync/atomic"

	lksdk "github.com/livekit/server-sdk-go/v2"
)

// PeerConfig configures a wbstream peer.
type PeerConfig struct {
	WSSURL      string
	DisplayName string
	RoomID      string // empty/"any" — create a new room
	E2EKey      []byte // optional 32-byte chacha20-poly1305 key
	SendQueue   int    // capacity of the outbound send buffer (default 4096)
}

// Peer is a wbstream LiveKit participant that exchanges MuxFrame payloads
// with other participants in the same room.
type Peer struct {
	cfg       PeerConfig
	room      *lksdk.Room
	e2e       *E2E
	roomID    string
	roomToken string

	onFrame func(*MuxFrame, lksdk.DataReceiveParams)

	sendQueue chan []byte
	closed    atomic.Bool
	done      chan struct{}
	wg        sync.WaitGroup
}

// New creates a peer but does not yet connect to LiveKit.
func New(cfg PeerConfig) (*Peer, error) {
	e2e, err := NewE2E(cfg.E2EKey)
	if err != nil {
		return nil, fmt.Errorf("init e2e: %w", err)
	}
	queue := cfg.SendQueue
	if queue <= 0 {
		queue = 4096
	}
	wssURL := cfg.WSSURL
	if wssURL == "" {
		wssURL = LiveKitWSSURL
	}
	cfg.WSSURL = wssURL
	return &Peer{
		cfg:       cfg,
		e2e:       e2e,
		sendQueue: make(chan []byte, queue),
		done:      make(chan struct{}),
	}, nil
}

// SetFrameHandler registers a callback fired for each decoded MuxFrame.
// onFrame must not block; queue further work elsewhere.
func (p *Peer) SetFrameHandler(handler func(*MuxFrame, lksdk.DataReceiveParams)) {
	p.onFrame = handler
}

// Connect performs the full HTTP handshake and joins the LiveKit room.
func (p *Peer) Connect(ctx context.Context) error {
	if p.closed.Load() {
		return errors.New("peer closed")
	}

	roomID, token, err := AcquireRoomToken(ctx, p.cfg.DisplayName, p.cfg.RoomID)
	if err != nil {
		return fmt.Errorf("acquire room token: %w", err)
	}
	p.roomID = roomID
	p.roomToken = token

	cb := &lksdk.RoomCallback{
		ParticipantCallback: lksdk.ParticipantCallback{
			OnDataReceived: p.handleData,
		},
		OnDisconnected: func() {
			log.Printf("wbstream room disconnected (room=%s)", p.roomID)
		},
	}
	room, err := lksdk.ConnectToRoomWithToken(p.cfg.WSSURL, token, cb, lksdk.WithAutoSubscribe(true))
	if err != nil {
		return fmt.Errorf("connect livekit: %w", err)
	}
	p.room = room

	p.wg.Add(1)
	go p.processSendQueue()
	log.Printf("wbstream peer joined room=%s as %q", p.roomID, p.cfg.DisplayName)
	return nil
}

// RoomID returns the actual room identifier the peer joined (useful when the
// caller passed empty/"any" and the SFU minted a fresh one).
func (p *Peer) RoomID() string {
	return p.roomID
}

// Send enqueues a MuxFrame for transmission. Returns ErrSendQueueFull when
// the buffer is saturated; callers should handle backpressure or drop.
func (p *Peer) Send(frame *MuxFrame) error {
	if p.closed.Load() {
		return errors.New("peer closed")
	}
	if frame == nil {
		return errors.New("frame is nil")
	}
	encoded := frame.Encode()
	if p.e2e.Active() {
		sealed, err := p.e2e.Seal(encoded)
		if err != nil {
			return fmt.Errorf("e2e seal: %w", err)
		}
		encoded = sealed
	}
	select {
	case p.sendQueue <- encoded:
		return nil
	default:
		return errors.New("send queue full")
	}
}

func (p *Peer) processSendQueue() {
	defer p.wg.Done()
	for {
		select {
		case <-p.done:
			return
		case payload, ok := <-p.sendQueue:
			if !ok {
				return
			}
			if p.room == nil || p.room.LocalParticipant == nil {
				continue
			}
			if err := p.room.LocalParticipant.PublishDataPacket(
				lksdk.UserData(payload),
				lksdk.WithDataPublishTopic("vk-turn-proxy/wbstream"),
				lksdk.WithDataPublishReliable(true),
			); err != nil {
				log.Printf("wbstream publish error: %v", err)
			}
		}
	}
}

func (p *Peer) handleData(payload []byte, params lksdk.DataReceiveParams) {
	if p.closed.Load() {
		return
	}
	body := payload
	if p.e2e.Active() {
		opened, err := p.e2e.Open(payload)
		if err != nil {
			log.Printf("wbstream e2e open: %v", err)
			return
		}
		body = opened
	}
	frame, err := DecodeMuxFrame(body)
	if err != nil {
		log.Printf("wbstream decode mux: %v", err)
		return
	}
	if handler := p.onFrame; handler != nil {
		handler(frame, params)
	}
}

// Close disconnects from the room and stops background goroutines.
func (p *Peer) Close() error {
	if !p.closed.CompareAndSwap(false, true) {
		return nil
	}
	close(p.done)
	if p.room != nil {
		p.room.Disconnect()
	}
	close(p.sendQueue)
	p.wg.Wait()
	return nil
}
