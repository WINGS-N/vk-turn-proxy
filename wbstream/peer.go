package wbstream

import (
	"context"
	"errors"
	"fmt"
	"log"
	"sync"
	"sync/atomic"
	"time"

	lksdk "github.com/livekit/server-sdk-go/v2"

	"github.com/cacggghp/vk-turn-proxy/internal/topicpool"
)

// reconnectInitialDelay is the first backoff step after a room kick before we
// try to rejoin. Exponential doubling caps at reconnectMaxDelay; cycle restarts
// on every successful Connect so a single drop does not poison future tries.
const (
	reconnectInitialDelay = 2 * time.Second
	reconnectMaxDelay     = 60 * time.Second
)

// PeerConfig configures a wbstream peer.
type PeerConfig struct {
	WSSURL      string
	DisplayName string
	RoomID      string // empty/"any" — create a new room
	E2EKey      []byte // optional 32-byte AES-256 key
	SendQueue   int    // capacity of the outbound send buffer (default 4096)
}

// Peer is a wbstream LiveKit participant that exchanges MuxFrame payloads
// with other participants in the same room.
type Peer struct {
	cfg       PeerConfig
	roomMu    sync.RWMutex
	room      *lksdk.Room
	e2e       *E2E
	roomID    string
	roomToken string

	onFrame func(*MuxFrame, lksdk.DataReceiveParams)

	sendQueue chan []byte
	closed    atomic.Bool
	done      chan struct{}
	wg        sync.WaitGroup

	correspondentsMu  sync.RWMutex
	correspondents    []string
	correspondentsSet map[string]struct{}
	rrSendIdx         atomic.Uint64

	siblingsMu sync.RWMutex
	siblings   map[string]struct{}

	reconnectCtx    context.Context
	reconnectCancel context.CancelFunc
	reconnecting    atomic.Bool
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
		cfg:               cfg,
		e2e:               e2e,
		sendQueue:         make(chan []byte, queue),
		done:              make(chan struct{}),
		correspondentsSet: map[string]struct{}{},
		siblings:          map[string]struct{}{},
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

	// Reconnect goroutine inherits a peer-scoped context cancelled by Close().
	// Capturing the caller's ctx here means a transient parent cancel does not
	// kill the reconnect loop forever.
	if p.reconnectCtx == nil {
		p.reconnectCtx, p.reconnectCancel = context.WithCancel(context.Background())
	}

	if err := p.joinRoom(ctx, true); err != nil {
		return err
	}

	p.wg.Add(1)
	go p.processSendQueue()
	return nil
}

// joinRoom acquires a token and connects to LiveKit. Used by both Connect()
// (initial join) and the reconnect goroutine. When freshSendQueue is true the
// caller is responsible for spawning processSendQueue.
func (p *Peer) joinRoom(ctx context.Context, initial bool) error {
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
			p.scheduleReconnect()
		},
		OnParticipantDisconnected: func(rp *lksdk.RemoteParticipant) {
			if rp != nil {
				p.removeCorrespondent(rp.Identity())
			}
		},
	}
	room, err := lksdk.ConnectToRoomWithToken(p.cfg.WSSURL, token, cb, lksdk.WithAutoSubscribe(true))
	if err != nil {
		return fmt.Errorf("connect livekit: %w", err)
	}
	p.roomMu.Lock()
	prev := p.room
	p.room = room
	p.roomMu.Unlock()
	if !initial && prev != nil {
		// Safety: an OnDisconnected handler may fire even after we already
		// observed the disconnect through the callback. Drop the stale handle.
		prev.Disconnect()
	}
	verb := "joined"
	if !initial {
		verb = "rejoined"
	}
	log.Printf("wbstream peer %s room=%s as %q", verb, p.roomID, p.cfg.DisplayName)
	return nil
}

// scheduleReconnect kicks off a background goroutine that re-joins the room
// after a kick / network drop. Multiple disconnect callbacks coalesce into a
// single reconnect attempt via the reconnecting flag.
func (p *Peer) scheduleReconnect() {
	if p.closed.Load() {
		return
	}
	if !p.reconnecting.CompareAndSwap(false, true) {
		return
	}
	go func() {
		defer p.reconnecting.Store(false)
		delay := reconnectInitialDelay
		for {
			if p.closed.Load() {
				return
			}
			select {
			case <-p.reconnectCtx.Done():
				return
			case <-time.After(delay):
			}
			if p.closed.Load() {
				return
			}
			attemptCtx, cancel := context.WithTimeout(p.reconnectCtx, 30*time.Second)
			err := p.joinRoom(attemptCtx, false)
			cancel()
			if err == nil {
				return
			}
			log.Printf("wbstream reconnect failed (room=%s): %v", p.cfg.RoomID, err)
			delay *= 2
			if delay > reconnectMaxDelay {
				delay = reconnectMaxDelay
			}
		}
	}()
}

// RoomID returns the actual room identifier the peer joined (useful when the
// caller passed empty/"any" and the SFU minted a fresh one).
func (p *Peer) RoomID() string {
	return p.roomID
}

// LocalIdentity returns the LiveKit identity assigned to this peer's own
// LocalParticipant. Empty until Connect succeeds.
func (p *Peer) LocalIdentity() string {
	p.roomMu.RLock()
	room := p.room
	p.roomMu.RUnlock()
	if room == nil || room.LocalParticipant == nil {
		return ""
	}
	return room.LocalParticipant.Identity()
}

// SetSiblings registers identities whose frames must be ignored even though
// they share the same room. Used by MultiPeer to suppress the cold-start
// broadcast loop where a sibling client identity would receive its peer's
// outbound MuxFrame and mistakenly inject it back into the local UDP bridge.
func (p *Peer) SetSiblings(identities []string) {
	p.siblingsMu.Lock()
	defer p.siblingsMu.Unlock()
	p.siblings = make(map[string]struct{}, len(identities))
	own := ""
	p.roomMu.RLock()
	room := p.room
	p.roomMu.RUnlock()
	if room != nil && room.LocalParticipant != nil {
		own = room.LocalParticipant.Identity()
	}
	for _, id := range identities {
		if id == "" || id == own {
			continue
		}
		p.siblings[id] = struct{}{}
	}
}

func (p *Peer) isSibling(identity string) bool {
	if identity == "" {
		return false
	}
	p.siblingsMu.RLock()
	_, ok := p.siblings[identity]
	p.siblingsMu.RUnlock()
	return ok
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
			p.roomMu.RLock()
			room := p.room
			p.roomMu.RUnlock()
			if room == nil || room.LocalParticipant == nil {
				continue
			}
			opts := []lksdk.DataPublishOption{
				lksdk.WithDataPublishTopic(topicpool.Pick()),
				lksdk.WithDataPublishReliable(true),
			}
			if dst := p.pickCorrespondent(); len(dst) > 0 {
				opts = append(opts, lksdk.WithDataPublishDestination(dst))
			}
			if err := room.LocalParticipant.PublishDataPacket(
				lksdk.UserData(payload),
				opts...,
			); err != nil {
				log.Printf("wbstream publish error: %v", err)
			}
		}
	}
}

// markCorrespondent registers a remote identity that has spoken to us. Only
// these identities are eligible as send destinations; siblings in the same
// room (e.g., the other N-1 client identities of a multi-identity client) get
// added on join via the participant callback but never become correspondents
// because they don't send to us.
func (p *Peer) markCorrespondent(identity string) {
	if identity == "" {
		return
	}
	p.correspondentsMu.Lock()
	if _, ok := p.correspondentsSet[identity]; !ok {
		p.correspondentsSet[identity] = struct{}{}
		p.correspondents = append(p.correspondents, identity)
	}
	p.correspondentsMu.Unlock()
}

func (p *Peer) removeCorrespondent(identity string) {
	if identity == "" {
		return
	}
	p.correspondentsMu.Lock()
	if _, ok := p.correspondentsSet[identity]; ok {
		delete(p.correspondentsSet, identity)
		for i, existing := range p.correspondents {
			if existing == identity {
				p.correspondents = append(p.correspondents[:i], p.correspondents[i+1:]...)
				break
			}
		}
	}
	p.correspondentsMu.Unlock()
}

// pickCorrespondent returns a single-element identity list for directional
// addressing or nil to fall back to broadcast (used during cold-start before
// the first inbound frame from any correspondent).
func (p *Peer) pickCorrespondent() []string {
	p.correspondentsMu.RLock()
	defer p.correspondentsMu.RUnlock()
	if len(p.correspondents) == 0 {
		return nil
	}
	idx := int(p.rrSendIdx.Add(1)-1) % len(p.correspondents)
	return []string{p.correspondents[idx]}
}

func (p *Peer) handleData(payload []byte, params lksdk.DataReceiveParams) {
	if p.closed.Load() {
		return
	}
	if p.isSibling(params.SenderIdentity) {
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
	p.markCorrespondent(params.SenderIdentity)
	if handler := p.onFrame; handler != nil {
		handler(frame, params)
	}
}

// Close disconnects from the room and stops background goroutines.
func (p *Peer) Close() error {
	if !p.closed.CompareAndSwap(false, true) {
		return nil
	}
	if p.reconnectCancel != nil {
		p.reconnectCancel()
	}
	close(p.done)
	p.roomMu.RLock()
	room := p.room
	p.roomMu.RUnlock()
	if room != nil {
		room.Disconnect()
	}
	close(p.sendQueue)
	p.wg.Wait()
	return nil
}
