package main

import (
	"context"
	"encoding/base64"
	"fmt"
	"log"
	"net"
	"sync"
	"sync/atomic"
	"time"

	lksdk "github.com/livekit/server-sdk-go/v2"

	"github.com/cacggghp/vk-turn-proxy/sessionproto"
	"github.com/cacggghp/vk-turn-proxy/wbstream"
)

// wbStreamSessionPool keeps one LiveKit-participant per room_id and forwards
// MuxFrame payloads to a shared UDP backend (the server's -udp-connect).
//
// Room IDs arrive dynamically via CLIENT_HELLO_TYPE_ROOM_EXCHANGE: the regular
// VK TURN handshake terminates at the server, server reads room_id /
// e2e_secret from the protobuf payload and asks the pool to join that room.
// No pre-configuration required.
type wbStreamSessionPool struct {
	connectAddr string

	mu      sync.Mutex
	rooms   map[string]*wbStreamSessionEntry
	closed  bool
	rootCtx context.Context
	cancel  context.CancelFunc
}

type wbStreamSessionEntry struct {
	roomID  string
	peer    *wbstream.Peer
	bridge  *wbStreamBackendBridge
	cancel  context.CancelFunc
	doneCh  chan struct{}
	created time.Time
}

func newWbStreamSessionPool(connectAddr string) *wbStreamSessionPool {
	ctx, cancel := context.WithCancel(context.Background())
	return &wbStreamSessionPool{
		connectAddr: connectAddr,
		rooms:       map[string]*wbStreamSessionEntry{},
		rootCtx:     ctx,
		cancel:      cancel,
	}
}

// PreJoin attaches the pool to an explicit room (for ops where the operator
// configures `-wb-stream-room-id` up-front instead of letting clients deliver
// it through CLIENT_HELLO_TYPE_ROOM_EXCHANGE).
func (p *wbStreamSessionPool) PreJoin(roomID, displayName, e2eSecretB64 string) error {
	exchange := &sessionproto.RoomDataExchange{
		Provider:    sessionproto.RoomProvider_ROOM_PROVIDER_WB_STREAM,
		RoomId:      roomID,
		DisplayName: displayName,
		E2EEnabled:  e2eSecretB64 != "",
	}
	if e2eSecretB64 != "" {
		decoded, err := base64.StdEncoding.DecodeString(e2eSecretB64)
		if err != nil {
			return fmt.Errorf("decode e2e secret: %w", err)
		}
		exchange.E2ESecret = decoded
	}
	return p.joinLocked(exchange)
}

// HandleExchange is the SetRoomExchangeSink-compatible callback. It is
// idempotent — second invocation for the same room_id keeps the existing
// peer and only logs.
func (p *wbStreamSessionPool) HandleExchange(exchange *sessionproto.RoomDataExchange, addr net.Addr) {
	if exchange == nil || exchange.GetProvider() != sessionproto.RoomProvider_ROOM_PROVIDER_WB_STREAM {
		return
	}
	roomID := exchange.GetRoomId()
	if roomID == "" {
		return
	}

	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return
	}
	if _, ok := p.rooms[roomID]; ok {
		p.mu.Unlock()
		log.Printf("wb-stream pool: room=%s already joined (peer=%s)", roomID, addr)
		return
	}
	p.mu.Unlock()

	if err := p.joinLocked(exchange); err != nil {
		log.Printf("wb-stream pool: join room=%s failed: %v", roomID, err)
	}
}

func (p *wbStreamSessionPool) joinLocked(exchange *sessionproto.RoomDataExchange) error {
	roomID := exchange.GetRoomId()
	displayName := exchange.GetDisplayName()
	if displayName == "" {
		displayName = "vk-turn-proxy-server"
	}

	var e2eKey []byte
	if exchange.GetE2EEnabled() {
		e2eKey = exchange.GetE2ESecret()
	}

	peer, err := wbstream.New(wbstream.PeerConfig{
		DisplayName: displayName,
		RoomID:      roomID,
		E2EKey:      e2eKey,
	})
	if err != nil {
		return fmt.Errorf("init peer: %w", err)
	}

	bridge := newWbStreamBackendBridge(peer, p.connectAddr)
	peer.SetFrameHandler(bridge.handleFrame)

	connectCtx, cancel := context.WithTimeout(p.rootCtx, 30*time.Second)
	defer cancel()
	if err := peer.Connect(connectCtx); err != nil {
		return fmt.Errorf("connect livekit: %w", err)
	}

	roomCtx, roomCancel := context.WithCancel(p.rootCtx)
	entry := &wbStreamSessionEntry{
		roomID:  peer.RoomID(),
		peer:    peer,
		bridge:  bridge,
		cancel:  roomCancel,
		doneCh:  make(chan struct{}),
		created: time.Now(),
	}

	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		_ = peer.Close()
		return fmt.Errorf("pool closed")
	}
	if _, exists := p.rooms[entry.roomID]; exists {
		p.mu.Unlock()
		_ = peer.Close()
		return nil
	}
	p.rooms[entry.roomID] = entry
	p.mu.Unlock()

	log.Printf("wb-stream pool: joined room=%s (e2e=%t, backend=%s)",
		entry.roomID, exchange.GetE2EEnabled(), p.connectAddr)
	go p.watchRoom(roomCtx, entry)
	return nil
}

func (p *wbStreamSessionPool) watchRoom(ctx context.Context, entry *wbStreamSessionEntry) {
	defer close(entry.doneCh)
	<-ctx.Done()
	entry.bridge.Close()
	_ = entry.peer.Close()
	p.mu.Lock()
	if cur, ok := p.rooms[entry.roomID]; ok && cur == entry {
		delete(p.rooms, entry.roomID)
	}
	p.mu.Unlock()
	log.Printf("wb-stream pool: closed room=%s after %s", entry.roomID, time.Since(entry.created).Round(time.Second))
}

// Close terminates every active LiveKit room.
func (p *wbStreamSessionPool) Close() {
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return
	}
	p.closed = true
	entries := make([]*wbStreamSessionEntry, 0, len(p.rooms))
	for _, e := range p.rooms {
		entries = append(entries, e)
	}
	p.rooms = map[string]*wbStreamSessionEntry{}
	p.mu.Unlock()
	p.cancel()
	for _, e := range entries {
		e.cancel()
	}
	for _, e := range entries {
		<-e.doneCh
	}
}

// ----- backend bridge -----

type wbStreamStreamKey struct {
	session [wbstream.SessionIDLen]byte
	stream  byte
}

type wbStreamBackendStream struct {
	conn   net.Conn
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

type wbStreamBackendBridge struct {
	peer        *wbstream.Peer
	connectAddr string

	mu      sync.Mutex
	streams map[wbStreamStreamKey]*wbStreamBackendStream

	inboundCount  atomic.Uint64
	outboundCount atomic.Uint64
}

func newWbStreamBackendBridge(peer *wbstream.Peer, connectAddr string) *wbStreamBackendBridge {
	return &wbStreamBackendBridge{
		peer:        peer,
		connectAddr: connectAddr,
		streams:     map[wbStreamStreamKey]*wbStreamBackendStream{},
	}
}

func (b *wbStreamBackendBridge) handleFrame(frame *wbstream.MuxFrame, _ lksdk.DataReceiveParams) {
	count := b.inboundCount.Add(1)
	if count == 1 || count%256 == 0 {
		log.Printf("wb-stream bridge ← DataPacket #%d (session=%x stream=%d, %d bytes)",
			count, frame.SessionID[:4], frame.StreamID, len(frame.Payload))
	}
	if b.connectAddr == "" {
		log.Printf("wb-stream bridge: no -udp-connect configured, dropping frame")
		return
	}
	key := wbStreamStreamKey{session: frame.SessionID, stream: frame.StreamID}
	b.mu.Lock()
	stream, ok := b.streams[key]
	if !ok {
		conn, err := net.DialTimeout("udp", b.connectAddr, 5*time.Second)
		if err != nil {
			b.mu.Unlock()
			log.Printf("wb-stream backend dial: %v", err)
			return
		}
		ctx, cancel := context.WithCancel(context.Background())
		stream = &wbStreamBackendStream{conn: conn, cancel: cancel}
		b.streams[key] = stream
		stream.wg.Add(1)
		go b.pumpFromBackend(ctx, key, stream)
		log.Printf("wb-stream bridge: new backend stream session=%x stream=%d → %s", frame.SessionID[:4], frame.StreamID, b.connectAddr)
	}
	b.mu.Unlock()

	if _, err := stream.conn.Write(frame.Payload); err != nil {
		log.Printf("wb-stream backend write (session=%x stream=%d): %v", frame.SessionID[:4], frame.StreamID, err)
	}
}

func (b *wbStreamBackendBridge) pumpFromBackend(ctx context.Context, key wbStreamStreamKey, stream *wbStreamBackendStream) {
	defer stream.wg.Done()
	buf := make([]byte, 1500)
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}
		_ = stream.conn.SetReadDeadline(time.Now().Add(30 * time.Second))
		n, err := stream.conn.Read(buf)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			netErr, ok := err.(net.Error)
			if ok && netErr.Timeout() {
				continue
			}
			log.Printf("wb-stream backend read (session=%x stream=%d): %v", key.session[:4], key.stream, err)
			b.dropStream(key)
			return
		}
		frame := &wbstream.MuxFrame{
			SessionID: key.session,
			StreamID:  key.stream,
			Payload:   append([]byte(nil), buf[:n]...),
		}
		if err := b.peer.Send(frame); err != nil {
			log.Printf("wb-stream send back: %v", err)
		}
	}
}

func (b *wbStreamBackendBridge) dropStream(key wbStreamStreamKey) {
	b.mu.Lock()
	stream, ok := b.streams[key]
	if ok {
		delete(b.streams, key)
	}
	b.mu.Unlock()
	if !ok {
		return
	}
	stream.cancel()
	_ = stream.conn.Close()
}

// Close terminates all active backend streams.
func (b *wbStreamBackendBridge) Close() {
	b.mu.Lock()
	streams := b.streams
	b.streams = map[wbStreamStreamKey]*wbStreamBackendStream{}
	b.mu.Unlock()
	for _, stream := range streams {
		stream.cancel()
		_ = stream.conn.Close()
	}
	for _, stream := range streams {
		stream.wg.Wait()
	}
}
