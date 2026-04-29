package main

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/pion/dtls/v3"
	"github.com/pion/dtls/v3/pkg/crypto/selfsign"

	lksdk "github.com/livekit/server-sdk-go/v2"

	"github.com/cacggghp/vk-turn-proxy/sessionproto"
	sessionmuv1 "github.com/cacggghp/vk-turn-proxy/sessionproto/mu/v1"
	"github.com/cacggghp/vk-turn-proxy/wbstream"
)

// runWbStreamClient drives -wb-stream-room-id mode: bridges a local UDP listen
// socket to a LiveKit room. Each remote endpoint that sends to -listen gets a
// stable (session_id, stream_id) inside MuxFrames and replies flow back to the
// same UDP peer.
func runWbStreamClient(opts clientOptions) error {
	var e2eKey []byte
	if opts.wbStreamE2ESecret != "" {
		decoded, err := base64.StdEncoding.DecodeString(opts.wbStreamE2ESecret)
		if err != nil {
			return fmt.Errorf("decode -wb-stream-e2e-secret: %w", err)
		}
		e2eKey = decoded
	}

	bridge, err := newProtectBridge(opts.protectSock)
	if err != nil {
		return fmt.Errorf("init protect bridge: %w", err)
	}
	if bridge != nil {
		defer func() { _ = bridge.Close() }()
		installProtectedNetDefaults(bridge)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	peer, err := wbstream.New(wbstream.PeerConfig{
		DisplayName: opts.wbStreamDisplayName,
		RoomID:      opts.wbStreamRoomID,
		E2EKey:      e2eKey,
	})
	if err != nil {
		return fmt.Errorf("init wbstream peer: %w", err)
	}

	udpAddr, err := net.ResolveUDPAddr("udp", opts.listen)
	if err != nil {
		return fmt.Errorf("resolve listen: %w", err)
	}
	udp, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return fmt.Errorf("listen udp: %w", err)
	}
	defer func() { _ = udp.Close() }()

	clientBridge := newWbStreamClientBridge(peer, udp)
	peer.SetFrameHandler(clientBridge.handleFrame)

	if err := peer.Connect(ctx); err != nil {
		return fmt.Errorf("connect livekit: %w", err)
	}
	log.Printf("wb-stream client listening on %s, room=%s", opts.listen, peer.RoomID())
	// Status markers consumed by ProxyTunnelService.waitForProxyWarmup. wb-stream
	// has no TURN/DTLS phase; treat the moment the LiveKit room is connected and
	// the local UDP listener is up as both auth_ready and dtls_ready. emitProxyStatus
	// writes via fmt.Println so the line lands without log-package timestamp prefix
	// (parser expects line.startsWith("PROXY_STATUS:")).
	emitProxyStatus("auth_ready")
	emitProxyStatus("ok")

	go clientBridge.pumpFromLocal(ctx)

	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, syscall.SIGTERM, syscall.SIGINT)
	<-signalChan
	log.Printf("Terminating wb-stream client...")
	cancel()
	_ = udp.Close()
	return peer.Close()
}

type wbStreamClientBridge struct {
	peer *wbstream.Peer
	udp  *net.UDPConn

	sessionID [wbstream.SessionIDLen]byte

	mu      sync.Mutex
	streams map[byte]*net.UDPAddr
	revIdx  map[string]byte
	nextID  byte

	outboundCount atomic.Uint64
	inboundCount  atomic.Uint64
}

func newWbStreamClientBridge(peer *wbstream.Peer, udp *net.UDPConn) *wbStreamClientBridge {
	bridge := &wbStreamClientBridge{
		peer:    peer,
		udp:     udp,
		streams: map[byte]*net.UDPAddr{},
		revIdx:  map[string]byte{},
	}
	if _, err := rand.Read(bridge.sessionID[:]); err != nil {
		log.Printf("warning: rand for session_id failed: %v", err)
	}
	return bridge
}

func (c *wbStreamClientBridge) pumpFromLocal(ctx context.Context) {
	buf := make([]byte, 1500)
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}
		n, peerAddr, err := c.udp.ReadFromUDP(buf)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			log.Printf("wb-stream client udp read: %v", err)
			return
		}
		streamID := c.streamForAddr(peerAddr)
		frame := &wbstream.MuxFrame{
			SessionID: c.sessionID,
			StreamID:  streamID,
			Payload:   append([]byte(nil), buf[:n]...),
		}
		count := c.outboundCount.Add(1)
		if count == 1 || count%256 == 0 {
			log.Printf("wb-stream client → DataPacket #%d (stream=%d, %d bytes from %s)", count, streamID, n, peerAddr)
		}
		if err := c.peer.Send(frame); err != nil {
			log.Printf("wb-stream client send: %v", err)
		}
	}
}

func (c *wbStreamClientBridge) handleFrame(frame *wbstream.MuxFrame, _ lksdk.DataReceiveParams) {
	count := c.inboundCount.Add(1)
	if count == 1 || count%256 == 0 {
		log.Printf("wb-stream client ← DataPacket #%d (stream=%d, %d bytes)", count, frame.StreamID, len(frame.Payload))
	}
	c.mu.Lock()
	addr := c.streams[frame.StreamID]
	c.mu.Unlock()
	if addr == nil {
		return
	}
	if _, err := c.udp.WriteToUDP(frame.Payload, addr); err != nil {
		log.Printf("wb-stream client udp write: %v", err)
	}
}

func (c *wbStreamClientBridge) streamForAddr(addr *net.UDPAddr) byte {
	key := addr.String()
	c.mu.Lock()
	defer c.mu.Unlock()
	if id, ok := c.revIdx[key]; ok {
		return id
	}
	id := c.nextID
	c.nextID++
	c.streams[id] = addr
	c.revIdx[key] = id
	return id
}

// runRoomExchangeMode opens a direct DTLS connection to -peer and sends one
// CLIENT_HELLO_TYPE_ROOM_EXCHANGE message carrying a RoomDataExchange payload.
// Used when "Exchange room data via VK TURN" is enabled — the short-lived
// handshake delivers the room id without spinning up the full VK TURN data
// plane. Going through actual VK TURN allocation (for DPI camouflage) is a
// follow-up; for now this is a direct DTLS dial.
func runRoomExchangeMode(opts clientOptions) error {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	addr, err := net.ResolveUDPAddr("udp", opts.peerAddr)
	if err != nil {
		return fmt.Errorf("resolve peer: %w", err)
	}
	udp, err := net.ListenPacket("udp", ":0")
	if err != nil {
		return fmt.Errorf("listen udp: %w", err)
	}
	defer func() { _ = udp.Close() }()

	dtlsConn, err := dialRoomExchangeDTLS(ctx, udp, addr)
	if err != nil {
		return fmt.Errorf("dtls handshake: %w", err)
	}
	defer func() { _ = dtlsConn.Close() }()

	exchange := &sessionproto.RoomDataExchange{
		Provider:    sessionproto.RoomProvider_ROOM_PROVIDER_WB_STREAM,
		RoomId:      opts.roomExchangeRoomID,
		DisplayName: opts.roomExchangeDisplayName,
		E2EEnabled:  opts.roomExchangeE2EEnabled,
	}
	if opts.roomExchangeE2ESecret != "" {
		decoded, err := base64.StdEncoding.DecodeString(opts.roomExchangeE2ESecret)
		if err != nil {
			return fmt.Errorf("decode -room-exchange-e2e-secret: %w", err)
		}
		exchange.E2ESecret = decoded
	}

	payload, err := sessionmuv1.BuildRoomExchangeHello(exchange)
	if err != nil {
		return fmt.Errorf("build hello: %w", err)
	}
	if _, err := dtlsConn.Write(payload); err != nil {
		return fmt.Errorf("write hello: %w", err)
	}
	log.Printf("room-exchange delivered to %s (room=%s, name=%q, e2e=%t)",
		opts.peerAddr, opts.roomExchangeRoomID, opts.roomExchangeDisplayName, opts.roomExchangeE2EEnabled)
	return nil
}

// installProtectedNetDefaults rewires Go's default resolver and HTTP transport
// so DNS lookups and HTTP/WSS dials performed by the LiveKit SDK (and any
// other library that uses net.DefaultResolver / http.DefaultTransport) bypass
// the VPN tun via VpnService.protect. Without this, the WireGuard tunnel that
// runs on top of us captures wb-stream's own signalling traffic and creates a
// "VPN through itself" loop — DNS to stream.wb.ru and wbstream01-el.wb.ru
// resolves through our own tun and times out.
//
// We can't use Go's default PreferGo resolver because /etc/resolv.conf on
// Android typically points at 127.0.0.1:53 (the OS's per-app stub) which is
// unreachable from a child process. The protectedResolver instead dials a
// known list of public DNS servers (yandex / google / cloudflare) over
// protect()-marked sockets.
func installProtectedNetDefaults(bridge *protectBridge) {
	resolver := newProtectedResolver(bridge, nil)
	netResolver := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			// Ignore the OS-supplied DNS server address; route through the first
			// reachable public resolver via a protect()-ed dialer instead.
			for _, candidate := range resolver.resolverAddrs {
				conn, err := resolver.dialer().DialContext(ctx, network, candidate)
				if err == nil {
					return conn, nil
				}
			}
			return nil, fmt.Errorf("no public DNS resolver reachable")
		},
	}
	net.DefaultResolver = netResolver
	http.DefaultTransport = &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		DialContext:           resolver.DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          16,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   30 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}
}

func dialRoomExchangeDTLS(ctx context.Context, conn net.PacketConn, peer *net.UDPAddr) (net.Conn, error) {
	cert, err := selfsign.GenerateSelfSigned()
	if err != nil {
		return nil, fmt.Errorf("self-signed cert: %w", err)
	}
	cfg := &dtls.Config{
		Certificates:         []tls.Certificate{cert},
		InsecureSkipVerify:   true,
		ExtendedMasterSecret: dtls.RequireExtendedMasterSecret,
		CipherSuites:         []dtls.CipherSuiteID{dtls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256},
	}
	dtlsConn, err := dtls.Client(conn, peer, cfg)
	if err != nil {
		return nil, err
	}
	if err := dtlsConn.HandshakeContext(ctx); err != nil {
		return nil, err
	}
	return dtlsConn, nil
}
