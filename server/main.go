package main

import (
	"context"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/cacggghp/vk-turn-proxy/internal/controlpath"
	"github.com/cacggghp/vk-turn-proxy/internal/panelclient"
	"github.com/cacggghp/vk-turn-proxy/internal/peerstore"
	"github.com/cacggghp/vk-turn-proxy/internal/pintls"
	"github.com/cacggghp/vk-turn-proxy/internal/relaygrpc"
	"github.com/cacggghp/vk-turn-proxy/internal/tokenaead"
	"github.com/cacggghp/vk-turn-proxy/internal/wgapply"
	"github.com/cacggghp/vk-turn-proxy/internal/wrap"
	"github.com/cacggghp/vk-turn-proxy/sessionproto"
	sessionmuv1 "github.com/cacggghp/vk-turn-proxy/sessionproto/mu/v1"
	"github.com/pion/dtls/v3"
	"github.com/pion/dtls/v3/pkg/crypto/selfsign"
	dtlsnet "github.com/pion/dtls/v3/pkg/net"
	pionudp "github.com/pion/transport/v4/udp"
	"google.golang.org/grpc/credentials"
)

const initialNegotiationTimeout = 750 * time.Millisecond

// relayVersion is the build version reported over the management gRPC. It is
// stamped from the git tag at build time via
// -ldflags "-X main.relayVersion=$(git describe --tags --always --dirty)"; the
// "dev" fallback is used for un-stamped local builds.
var relayVersion = "dev"

var serverUI *serverTUI

// flowRegistry adapts the always-on serverUI stream registry to the Relay gRPC
// FlowProvider. It reads the global lazily (the methods are nil-safe) so it can
// be wired before serverUI is created.
type flowRegistry struct{}

func (flowRegistry) Flows() []relaygrpc.Flow        { return serverUI.Flows() }
func (flowRegistry) FlowStats() relaygrpc.FlowStats { return serverUI.FlowStats() }

const (
	serverUDPReadBufferBytes  = 4 << 20
	serverUDPWriteBufferBytes = 4 << 20
)

type udpBufferTunable interface {
	SetReadBuffer(bytes int) error
	SetWriteBuffer(bytes int) error
}

func tuneUDPBuffers(target any, label string) {
	conn, ok := target.(udpBufferTunable)
	if !ok || conn == nil {
		return
	}
	if err := conn.SetReadBuffer(serverUDPReadBufferBytes); err != nil {
		log.Printf("UDP read buffer tune failed for %s: %s", label, err)
	}
	if err := conn.SetWriteBuffer(serverUDPWriteBufferBytes); err != nil {
		log.Printf("UDP write buffer tune failed for %s: %s", label, err)
	}
}

type transportBackends struct {
	udpConnect string
	tcpConnect string
}

func (backends transportBackends) supportsDatagram() bool {
	return strings.TrimSpace(backends.udpConnect) != ""
}

func (backends transportBackends) supportsTCP() bool {
	return strings.TrimSpace(backends.tcpConnect) != ""
}

func (backends transportBackends) describe() string {
	parts := make([]string, 0, 2)
	if backends.supportsDatagram() {
		parts = append(parts, "udp="+backends.udpConnect)
	}
	if backends.supportsTCP() {
		parts = append(parts, "tcp="+backends.tcpConnect)
	}
	if len(parts) == 0 {
		return "<none>"
	}
	return strings.Join(parts, " ")
}

func allowsMu(mode sessionproto.Mode) bool {
	return mode != sessionproto.ModeMainline
}

func resolveServerBackends(connect, udpConnect, tcpConnect string, tcpAlias bool) (transportBackends, error) {
	connect = strings.TrimSpace(connect)
	udpConnect = strings.TrimSpace(udpConnect)
	tcpConnect = strings.TrimSpace(tcpConnect)

	if connect != "" && (udpConnect != "" || tcpConnect != "") {
		return transportBackends{}, fmt.Errorf("-connect cannot be combined with -udp-connect or -tcp-connect")
	}

	if connect != "" {
		if tcpAlias {
			tcpConnect = connect
		} else {
			udpConnect = connect
		}
	}

	backends := transportBackends{
		udpConnect: udpConnect,
		tcpConnect: tcpConnect,
	}
	if !backends.supportsDatagram() && !backends.supportsTCP() {
		return transportBackends{}, fmt.Errorf("at least one backend is required")
	}
	return backends, nil
}

func supportedTransportsForHello(mode sessionproto.Mode, backends transportBackends, hello *sessionproto.ClientHello) []sessionproto.TransportMode {
	supported := make([]sessionproto.TransportMode, 0, 2)
	if backends.supportsDatagram() {
		supported = append(supported, sessionproto.TransportMode_TRANSPORT_MODE_DATAGRAM)
	}
	helloType := sessionproto.ClientHelloType_CLIENT_HELLO_TYPE_UNSPECIFIED
	if hello != nil {
		helloType = hello.GetType()
	}
	if helloType != sessionproto.ClientHelloType_CLIENT_HELLO_TYPE_SESSION && mode != sessionproto.ModeMu && backends.supportsTCP() {
		supported = append(supported, sessionproto.TransportMode_TRANSPORT_MODE_TCP)
	}
	return sessionproto.NormalizeSupportedTransports(supported)
}

func requestedTransportForHello(hello *sessionproto.ClientHello) sessionproto.TransportMode {
	if hello == nil {
		return sessionproto.TransportMode_TRANSPORT_MODE_DATAGRAM
	}
	requested := hello.GetRequestedTransport()
	if hello.GetVersion() < sessionmuv1.ProtocolVersion || requested == sessionproto.TransportMode_TRANSPORT_MODE_UNSPECIFIED {
		return sessionproto.TransportMode_TRANSPORT_MODE_DATAGRAM
	}
	return requested
}

func firstSupportedTransport(supported []sessionproto.TransportMode) sessionproto.TransportMode {
	normalized := sessionproto.NormalizeSupportedTransports(supported)
	if len(normalized) == 0 {
		return sessionproto.TransportMode_TRANSPORT_MODE_UNSPECIFIED
	}
	return normalized[0]
}

func supportedTcpFlavorsForServer() []sessionproto.TcpTransportFlavor {
	// Only KCP+smux is supported. DIRECT_SMUX (smux straight over DTLS) was removed: smux
	// needs a reliable ordered byte stream, while the DTLS relay is a lossy, record-oriented
	// datagram transport, so smux's sub-record reads tripped pion/dtls "buffer is too small".
	// KCP is the required datagram-to-stream adapter. Matches the reference upstream (Moroka8).
	return []sessionproto.TcpTransportFlavor{
		sessionproto.TcpTransportFlavor_TCP_TRANSPORT_FLAVOR_LEGACY_KCP_SMUX,
	}
}

func selectTcpFlavorForHello(hello *sessionproto.ClientHello) (sessionproto.TcpTransportFlavor, []sessionproto.TcpTransportFlavor) {
	supported := supportedTcpFlavorsForServer()
	if hello == nil {
		return sessionproto.TcpTransportFlavor_TCP_TRANSPORT_FLAVOR_LEGACY_KCP_SMUX, supported
	}
	clientSupported := sessionproto.NormalizeSupportedTcpFlavors(hello.GetSupportedTcpFlavors())
	if len(clientSupported) == 0 {
		return sessionproto.TcpTransportFlavor_TCP_TRANSPORT_FLAVOR_LEGACY_KCP_SMUX, supported
	}
	preferred := hello.GetPreferredTcpFlavor()
	if preferred != sessionproto.TcpTransportFlavor_TCP_TRANSPORT_FLAVOR_UNSPECIFIED &&
		sessionproto.HasSupportedTcpFlavor(clientSupported, preferred) &&
		sessionproto.HasSupportedTcpFlavor(supported, preferred) {
		return preferred, supported
	}
	// DIRECT_SMUX is no longer selectable (removed as a broken transport); always fall back
	// to KCP+smux, including for older clients that still advertise DIRECT_SMUX.
	return sessionproto.TcpTransportFlavor_TCP_TRANSPORT_FLAVOR_LEGACY_KCP_SMUX, supported
}

func selectTransportForHello(mode sessionproto.Mode, backends transportBackends, hello *sessionproto.ClientHello) (sessionproto.TransportMode, []sessionproto.TransportMode, string) {
	supported := supportedTransportsForHello(mode, backends, hello)
	requested := requestedTransportForHello(hello)

	switch requested {
	case sessionproto.TransportMode_TRANSPORT_MODE_TCP:
		if hello != nil && hello.GetType() == sessionproto.ClientHelloType_CLIENT_HELLO_TYPE_SESSION {
			return firstSupportedTransport(supported), supported, "mu session mode does not support tcp transport"
		}
		if mode == sessionproto.ModeMu {
			return firstSupportedTransport(supported), supported, "server session mode does not support tcp transport"
		}
		if !backends.supportsTCP() {
			return firstSupportedTransport(supported), supported, "server tcp transport is unavailable"
		}
		return sessionproto.TransportMode_TRANSPORT_MODE_TCP, supported, ""
	case sessionproto.TransportMode_TRANSPORT_MODE_DATAGRAM:
		if !backends.supportsDatagram() {
			return firstSupportedTransport(supported), supported, "server datagram transport is unavailable"
		}
		return sessionproto.TransportMode_TRANSPORT_MODE_DATAGRAM, supported, ""
	default:
		return firstSupportedTransport(supported), supported, fmt.Sprintf("unsupported transport: %s", requested)
	}
}

type streamEntry struct {
	id       byte
	key      string
	clientIP string
	conn     net.Conn
}

type UserSession struct {
	ID          string
	Conns       []streamEntry
	Lock        sync.RWMutex
	Ctx         context.Context
	Cancel      context.CancelFunc
	Manager     *SessionManager
	cleanupOnce sync.Once
}

type SessionManager struct {
	Sessions map[string]*UserSession
	Lock     sync.RWMutex
}

func (s *SessionManager) GetOrCreate(ctx context.Context, id string) (*UserSession, error) {
	s.Lock.Lock()
	defer s.Lock.Unlock()

	if session, ok := s.Sessions[id]; ok {
		return session, nil
	}

	sessionCtx, cancel := context.WithCancel(ctx)
	session := &UserSession{
		ID:      id,
		Conns:   make([]streamEntry, 0),
		Manager: s,
		Ctx:     sessionCtx,
		Cancel:  cancel,
	}
	s.Sessions[id] = session
	if serverUI != nil {
		serverUI.registerSession(id)
	}
	log.Printf("Session %s created", id)

	return session, nil
}

func (s *UserSession) AddConn(id byte, key string, clientIP string, conn net.Conn) {
	s.Lock.Lock()
	defer s.Lock.Unlock()

	for i, entry := range s.Conns {
		if entry.id == id {
			if closeErr := entry.conn.Close(); closeErr != nil {
				log.Printf("Session %s failed to replace DTLS connection for stream %d: %v", s.ID, id, closeErr)
			}
			s.Conns[i].conn = conn
			s.Conns[i].key = key
			s.Conns[i].clientIP = clientIP
			return
		}
	}

	s.Conns = append(s.Conns, streamEntry{id: id, key: key, clientIP: clientIP, conn: conn})
}

func (s *UserSession) RemoveConn(id byte, conn net.Conn) {
	s.Lock.Lock()

	for i, entry := range s.Conns {
		if entry.id == id && entry.conn == conn {
			s.Conns = append(s.Conns[:i], s.Conns[i+1:]...)
			break
		}
	}
	shouldCleanup := len(s.Conns) == 0
	s.Lock.Unlock()
	if shouldCleanup {
		s.Cleanup()
	}
}

func (s *UserSession) ActiveConnCount() uint32 {
	s.Lock.RLock()
	defer s.Lock.RUnlock()
	return uint32(len(s.Conns))
}

func (s *UserSession) Cleanup() {
	s.cleanupOnce.Do(func() {
		s.Cancel()

		s.Manager.Lock.Lock()
		delete(s.Manager.Sessions, s.ID)
		s.Manager.Lock.Unlock()
		if serverUI != nil {
			serverUI.unregisterSession(s.ID)
		}

		s.Lock.Lock()
		for _, entry := range s.Conns {
			_ = entry.conn.Close()
		}
		s.Conns = nil
		s.Lock.Unlock()
	})
}

func readInitialHelloOrLegacy(conn net.Conn, mode sessionproto.Mode) (*sessionproto.ClientHello, []byte, bool, error) {
	buf := make([]byte, 1600)
	if err := conn.SetReadDeadline(time.Now().Add(initialNegotiationTimeout)); err != nil {
		return nil, nil, false, err
	}
	n, err := conn.Read(buf)
	if clearErr := conn.SetReadDeadline(time.Time{}); clearErr != nil {
		return nil, nil, false, clearErr
	}
	if err != nil {
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			if mode == sessionproto.ModeMu {
				return nil, nil, false, fmt.Errorf("timed out waiting for mu hello")
			}
			return nil, nil, false, nil
		}
		return nil, nil, false, err
	}

	payload := append([]byte(nil), buf[:n]...)
	if sessionPayload, ok := sessionproto.ParseControlSessionRequest(payload); ok {
		hello, parseErr := sessionproto.ParseClientHelloMessage(sessionPayload)
		if parseErr != nil {
			return nil, nil, false, fmt.Errorf("invalid mu hello: %w", parseErr)
		}
		if validateErr := validateClientHelloForVersion(hello); validateErr != nil {
			return nil, nil, false, fmt.Errorf("invalid mu hello: %w", validateErr)
		}
		return hello, nil, true, nil
	}
	hello, parseErr := sessionproto.ParseClientHelloMessage(payload)
	if parseErr != nil {
		if mode == sessionproto.ModeMu {
			return nil, nil, false, fmt.Errorf("invalid mu hello: %w", parseErr)
		}
		return nil, payload, false, nil
	}
	if validateErr := validateClientHelloForVersion(hello); validateErr != nil {
		if mode == sessionproto.ModeMu {
			return nil, nil, false, fmt.Errorf("invalid mu hello: %w", validateErr)
		}
		return nil, payload, false, nil
	}
	return hello, nil, false, nil
}

func logInitialNegotiationPayload(conn net.Conn, hello *sessionproto.ClientHello, firstPacket []byte, wrappedSession bool) {
	if hello != nil {
		if wrappedSession {
			log.Printf("protobuf initial wrapped session hello from %s: %s", conn.RemoteAddr(), describeClientHello(hello))
			return
		}
		log.Printf("protobuf initial hello from %s: %s", conn.RemoteAddr(), describeClientHello(hello))
		return
	}
	if len(firstPacket) == 0 {
		log.Printf("no initial protobuf hello from %s", conn.RemoteAddr())
		return
	}
	if probePayload, ok := sessionproto.ParseControlProbeRequest(firstPacket); ok {
		probeHello, err := sessionproto.ParseClientHelloMessage(probePayload)
		if err == nil {
			log.Printf("protobuf initial wrapped probe from %s: %s", conn.RemoteAddr(), describeClientHello(probeHello))
			return
		}
	}
	prefixLen := min(len(firstPacket), 16)
	log.Printf(
		"mainline payload from %s: %d bytes, prefix=%x",
		conn.RemoteAddr(),
		len(firstPacket),
		firstPacket[:prefixLen],
	)
}

func runLegacyStream(
	ctx context.Context,
	conn net.Conn,
	connectAddr string,
	firstPacket []byte,
	mode sessionproto.Mode,
	backends transportBackends,
) error {
	streamKey := ""
	clientIP := clientIPFromAddr(conn.RemoteAddr())
	if serverUI != nil {
		streamKey = serverUI.nextStreamKey("mainline")
		serverUI.registerStream(streamKey, "mainline", 0, conn.RemoteAddr().String(), clientIP, "", 0)
		defer serverUI.unregisterStream(streamKey)
	}
	serverConn, err := net.Dial("udp", connectAddr)
	if err != nil {
		return err
	}
	tuneUDPBuffers(serverConn, "mainline backend")
	defer func() {
		if closeErr := serverConn.Close(); closeErr != nil {
			log.Printf("failed to close outgoing connection: %s", closeErr)
		}
	}()

	if len(firstPacket) > 0 {
		if handled, controlErr := handleMainlineControlPacket(conn, firstPacket, mode, backends); handled {
			if controlErr != nil {
				return controlErr
			}
			firstPacket = nil
		}
		if len(firstPacket) > 0 {
			if err := serverConn.SetWriteDeadline(time.Now().Add(30 * time.Second)); err != nil {
				return err
			}
			if _, err := serverConn.Write(firstPacket); err != nil {
				return err
			}
			if serverUI != nil {
				serverUI.addStreamRx(streamKey, clientIP, len(firstPacket))
			}
		}
	}

	var wg sync.WaitGroup
	wg.Add(2)

	ctx2, cancel2 := context.WithCancel(ctx)
	defer cancel2()
	context.AfterFunc(ctx2, func() {
		if err := conn.SetDeadline(time.Now()); err != nil {
			log.Printf("failed to set incoming deadline: %s", err)
		}
		if err := serverConn.SetDeadline(time.Now()); err != nil {
			log.Printf("failed to set outgoing deadline: %s", err)
		}
	})

	go func() {
		defer wg.Done()
		defer cancel2()
		buf := make([]byte, 1600)
		for {
			select {
			case <-ctx2.Done():
				return
			default:
			}
			if err := conn.SetReadDeadline(time.Now().Add(30 * time.Minute)); err != nil {
				log.Printf("Failed: %s", err)
				return
			}
			n, readErr := conn.Read(buf)
			if readErr != nil {
				log.Printf("Failed: %s", readErr)
				return
			}
			if handled, controlErr := handleMainlineControlPacket(conn, buf[:n], mode, backends); handled {
				if controlErr != nil {
					log.Printf("Failed: %s", controlErr)
					return
				}
				continue
			}
			if handled, controlErr := handleControlHeartbeatPacket(conn, buf[:n], streamKey, controlpath.HeartbeatMeta{
				SessionMode: string(sessionproto.ModeMainline),
				ControlPath: controlpath.PathTurnDTLS,
				Provider:    controlpath.ProviderTurn,
				Transport:   sessionproto.TransportMode_TRANSPORT_MODE_DATAGRAM,
				ActiveFlows: 1,
			}); handled {
				if controlErr != nil {
					log.Printf("Failed: %s", controlErr)
					return
				}
				continue
			}

			if err := serverConn.SetWriteDeadline(time.Now().Add(30 * time.Minute)); err != nil {
				log.Printf("Failed: %s", err)
				return
			}
			if _, writeErr := serverConn.Write(buf[:n]); writeErr != nil {
				log.Printf("Failed: %s", writeErr)
				return
			}
			if serverUI != nil {
				serverUI.addStreamRx(streamKey, clientIP, n)
			}
		}
	}()

	go func() {
		defer wg.Done()
		defer cancel2()
		buf := make([]byte, 1600)
		for {
			select {
			case <-ctx2.Done():
				return
			default:
			}
			if err := serverConn.SetReadDeadline(time.Now().Add(30 * time.Minute)); err != nil {
				log.Printf("Failed: %s", err)
				return
			}
			n, readErr := serverConn.Read(buf)
			if readErr != nil {
				log.Printf("Failed: %s", readErr)
				return
			}

			if err := conn.SetWriteDeadline(time.Now().Add(30 * time.Minute)); err != nil {
				log.Printf("Failed: %s", err)
				return
			}
			if _, writeErr := conn.Write(buf[:n]); writeErr != nil {
				log.Printf("Failed: %s", writeErr)
				return
			}
			if serverUI != nil {
				serverUI.addStreamTx(streamKey, clientIP, n)
			}
		}
	}()

	wg.Wait()
	return nil
}

func writeMuxSessionHelloResponse(
	conn net.Conn,
	version uint32,
	muxSupported bool,
	errorText string,
	controlHeartbeatSupported bool,
	selectedTransport sessionproto.TransportMode,
	supportedTransports []sessionproto.TransportMode,
	wrappedSession bool,
) error {
	return writeMuxSessionHelloResponseWithWrap(
		conn,
		version,
		muxSupported,
		errorText,
		controlHeartbeatSupported,
		selectedTransport,
		supportedTransports,
		wrappedSession,
		sessionproto.WrapCipher_WRAP_CIPHER_UNSPECIFIED,
	)
}

func writeMuxSessionHelloResponseWithWrap(
	conn net.Conn,
	version uint32,
	muxSupported bool,
	errorText string,
	controlHeartbeatSupported bool,
	selectedTransport sessionproto.TransportMode,
	supportedTransports []sessionproto.TransportMode,
	wrappedSession bool,
	selectedWrapCipher sessionproto.WrapCipher,
) error {
	payload, err := buildServerHelloForVersionWithWrap(
		version,
		muxSupported,
		errorText,
		controlHeartbeatSupported,
		selectedTransport,
		supportedTransports,
		nil,
		sessionproto.TcpTransportFlavor_TCP_TRANSPORT_FLAVOR_UNSPECIFIED,
		selectedWrapCipher,
	)
	if err != nil {
		return err
	}
	if wrappedSession && version >= sessionmuv1.ProtocolVersion {
		return writeRawPacket(conn, sessionproto.BuildControlSessionResponse(payload))
	}
	return writeRawPacket(conn, payload)
}

type roomExchangeHandler func(*sessionproto.RoomDataExchange, net.Addr)

var roomExchangeSink atomic.Pointer[roomExchangeHandler]

// SetRoomExchangeSink registers a callback invoked for every received
// CLIENT_HELLO_TYPE_ROOM_EXCHANGE. Pass nil to clear.
func SetRoomExchangeSink(fn roomExchangeHandler) {
	if fn == nil {
		roomExchangeSink.Store(nil)
		return
	}
	roomExchangeSink.Store(&fn)
}

func handleRoomExchange(conn net.Conn, hello *sessionproto.ClientHello) error {
	exchange := hello.GetRoomExchange()
	if exchange == nil {
		log.Printf("room exchange from %s: missing payload", conn.RemoteAddr())
		return fmt.Errorf("missing room exchange payload")
	}
	log.Printf(
		"room exchange from %s: provider=%s room_id=%q display_name=%q e2e=%t e2e_secret_len=%d",
		conn.RemoteAddr(),
		exchange.GetProvider(),
		exchange.GetRoomId(),
		exchange.GetDisplayName(),
		exchange.GetE2EEnabled(),
		len(exchange.GetE2ESecret()),
	)
	if ptr := roomExchangeSink.Load(); ptr != nil {
		(*ptr)(exchange, conn.RemoteAddr())
	}
	return nil
}

func runMuStream(ctx context.Context, conn net.Conn, manager *SessionManager, connectAddr string, hello *sessionproto.ClientHello, wrappedSession bool, wrapPol *wrapPolicy, wrapListener *wrap.Listener) error {
	sessionID := hex.EncodeToString(hello.GetSessionId())
	streamID := byte(hello.GetStreamId())
	clientIP := clientIPFromAddr(conn.RemoteAddr())
	streamKey := ""
	if serverUI != nil {
		streamKey = serverUI.nextStreamKey("mu")
		serverUI.registerStream(
			streamKey,
			fmt.Sprintf("mu/v%d", hello.GetVersion()),
			hello.GetVersion(),
			conn.RemoteAddr().String(),
			clientIP,
			sessionID,
			streamID,
		)
		defer serverUI.unregisterStream(streamKey)
	}
	log.Printf(
		"protobuf mu session hello from %s: %s",
		conn.RemoteAddr(),
		describeClientHello(hello),
	)

	session, err := manager.GetOrCreate(ctx, sessionID)
	if err != nil {
		return err
	}
	serverConn, err := net.Dial("udp", connectAddr)
	if err != nil {
		return err
	}
	tuneUDPBuffers(serverConn, "mu backend")
	defer func() {
		if closeErr := serverConn.Close(); closeErr != nil {
			log.Printf("failed to close mu outgoing connection: %s", closeErr)
		}
	}()

	session.AddConn(streamID, streamKey, clientIP, conn)
	defer session.RemoveConn(streamID, conn)

	selectedWrap, wrapCipherInstance := negotiateWrapForSession(conn.RemoteAddr(), hello, wrapPol)

	if err := writeMuxSessionHelloResponseWithWrap(
		conn,
		hello.GetVersion(),
		true,
		"",
		true,
		sessionproto.TransportMode_TRANSPORT_MODE_DATAGRAM,
		[]sessionproto.TransportMode{sessionproto.TransportMode_TRANSPORT_MODE_DATAGRAM},
		wrappedSession,
		selectedWrap,
	); err != nil {
		return err
	}

	// Enable WRAP on the underlying StatefulConn AFTER the ServerHello
	// has been written raw. From the next outbound record on, all
	// DTLS-encrypted ApplicationData goes SRTP-shaped; the client's
	// receive side auto-detects either format so the brief asymmetry
	// during ServerHello in flight never desyncs the stream.
	if wrapCipherInstance != nil && wrapListener != nil {
		if sc := wrapListener.Lookup(conn.RemoteAddr()); sc != nil {
			sc.Enable(wrapCipherInstance)
			log.Printf("WRAP active on session for %s: cipher=%s", conn.RemoteAddr(), selectedWrap)
		} else {
			log.Printf("WRAP enable skipped for %s: no StatefulConn tracked", conn.RemoteAddr())
		}
	}

	log.Printf("New stream %d for session %s from %s", streamID, sessionID, conn.RemoteAddr())

	var wg sync.WaitGroup
	wg.Add(2)

	ctx2, cancel2 := context.WithCancel(ctx)
	defer cancel2()
	context.AfterFunc(ctx2, func() {
		if err := conn.SetDeadline(time.Now()); err != nil {
			log.Printf("failed to set mu incoming deadline: %s", err)
		}
		if err := serverConn.SetDeadline(time.Now()); err != nil {
			log.Printf("failed to set mu outgoing deadline: %s", err)
		}
	})

	go func() {
		defer wg.Done()
		defer cancel2()
		buf := make([]byte, 1600)
		for {
			select {
			case <-ctx2.Done():
				return
			default:
			}
			if err := conn.SetReadDeadline(time.Now().Add(30 * time.Minute)); err != nil {
				log.Printf("Failed: %s", err)
				return
			}
			n, readErr := conn.Read(buf)
			if readErr != nil {
				log.Printf("Failed: %s", readErr)
				return
			}
			hbMeta := controlpath.HeartbeatMeta{
				SessionMode: string(sessionproto.ModeMu),
				ControlPath: controlpath.PathTurnDTLS,
				Provider:    controlpath.ProviderTurn,
				Transport:   sessionproto.TransportMode_TRANSPORT_MODE_DATAGRAM,
				ActiveFlows: session.ActiveConnCount(),
			}
			// Managed clients announce their client id on the mu session hello; echo
			// that client's cached traffic-limit usage back so the app can show it.
			applyUsageToHeartbeat(&hbMeta, hello.GetClientId())
			if handled, controlErr := handleControlHeartbeatPacket(conn, buf[:n], streamKey, hbMeta); handled {
				if controlErr != nil {
					log.Printf("Failed: %s", controlErr)
					return
				}
				continue
			}

			if err := serverConn.SetWriteDeadline(time.Now().Add(30 * time.Minute)); err != nil {
				log.Printf("Failed: %s", err)
				return
			}
			if _, writeErr := serverConn.Write(buf[:n]); writeErr != nil {
				log.Printf("Failed: %s", writeErr)
				return
			}
			if serverUI != nil {
				serverUI.addStreamRx(streamKey, clientIP, n)
			}
		}
	}()

	go func() {
		defer wg.Done()
		defer cancel2()
		buf := make([]byte, 1600)
		for {
			select {
			case <-ctx2.Done():
				return
			default:
			}
			if err := serverConn.SetReadDeadline(time.Now().Add(30 * time.Minute)); err != nil {
				log.Printf("Failed: %s", err)
				return
			}
			n, readErr := serverConn.Read(buf)
			if readErr != nil {
				log.Printf("Failed: %s", readErr)
				return
			}

			if err := conn.SetWriteDeadline(time.Now().Add(30 * time.Minute)); err != nil {
				log.Printf("Failed: %s", err)
				return
			}
			if _, writeErr := conn.Write(buf[:n]); writeErr != nil {
				log.Printf("Failed: %s", writeErr)
				return
			}
			if serverUI != nil {
				serverUI.addStreamTx(streamKey, clientIP, n)
			}
		}
	}()

	wg.Wait()
	return nil
}

func handleConnection(
	ctx context.Context,
	conn net.Conn,
	manager *SessionManager,
	backends transportBackends,
	mode sessionproto.Mode,
	wrapPol *wrapPolicy,
	wrapListener *wrap.Listener,
) error {
	dtlsConn, ok := conn.(*dtls.Conn)
	if !ok {
		return fmt.Errorf("unexpected connection type")
	}

	handshakeCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	if err := dtlsConn.HandshakeContext(handshakeCtx); err != nil {
		return err
	}

	hello, firstPacket, wrappedSession, err := readInitialHelloOrLegacy(conn, mode)
	if err != nil {
		return err
	}
	logInitialNegotiationPayload(conn, hello, firstPacket, wrappedSession)

	handledWrappedControlProbe := false
	for hello == nil && len(firstPacket) > 0 {
		if handled, controlErr := handleMainlineControlPacket(conn, firstPacket, mode, backends); handled {
			if controlErr != nil {
				return controlErr
			}
			handledWrappedControlProbe = true
			hello, firstPacket, wrappedSession, err = readInitialHelloOrLegacy(conn, mode)
			if err != nil {
				if err == io.EOF {
					return nil
				}
				return err
			}
			logInitialNegotiationPayload(conn, hello, firstPacket, wrappedSession)
			continue
		}
		break
	}
	if handledWrappedControlProbe && hello == nil && len(firstPacket) == 0 {
		log.Printf("no data after wrapped mainline probe from %s; closing probe connection", conn.RemoteAddr())
		return nil
	}

	for hello != nil &&
		(hello.GetType() == sessionproto.ClientHelloType_CLIENT_HELLO_TYPE_PROBE ||
			hello.GetType() == sessionproto.ClientHelloType_CLIENT_HELLO_TYPE_PROVISION) {
		if hello.GetType() == sessionproto.ClientHelloType_CLIENT_HELLO_TYPE_PROVISION {
			// PROVISION is a non-terminal prefix hello: answer it and keep the
			// connection for the session hello that follows, so the client reuses
			// this same DTLS worker connection instead of reconnecting.
			if err := handleProvision(conn, hello); err != nil {
				return err
			}
			hello, firstPacket, wrappedSession, err = readInitialHelloOrLegacy(conn, mode)
			if err != nil {
				return err
			}
			if hello != nil {
				log.Printf(
					"protobuf follow-up hello after provision from %s: %s",
					conn.RemoteAddr(),
					describeClientHello(hello),
				)
			}
			continue
		}
		selectedTransport, supportedTransports, errorText := selectTransportForHello(mode, backends, hello)
		muSupported := allowsMu(mode) && errorText == ""
		selectedTcpFlavor, supportedTcpFlavors := selectTcpFlavorForHello(hello)
		log.Printf(
			"protobuf direct probe from %s: version=%d requested_transport=%s selected_transport=%s mu_supported=%t selected_tcp_flavor=%s error=%q",
			conn.RemoteAddr(),
			hello.GetVersion(),
			requestedTransportForHello(hello),
			selectedTransport,
			muSupported,
			selectedTcpFlavor,
			errorText,
		)
		if err := writeServerHelloForVersionWithTcpFlavor(
			conn,
			hello.GetVersion(),
			muSupported,
			errorText,
			true,
			selectedTransport,
			supportedTransports,
			supportedTcpFlavors,
			selectedTcpFlavor,
		); err != nil {
			return err
		}
		if errorText != "" {
			return fmt.Errorf("%s", errorText)
		}
		if selectedTransport == sessionproto.TransportMode_TRANSPORT_MODE_TCP {
			log.Printf("switching %s to tcp data path (flavor=%s)", conn.RemoteAddr(), selectedTcpFlavor)
			return handleTCPConnection(ctx, dtlsConn, backends.tcpConnect, selectedTcpFlavor)
		}
		hello, firstPacket, wrappedSession, err = readInitialHelloOrLegacy(conn, mode)
		if err != nil {
			return err
		}
		if hello != nil {
			log.Printf("protobuf follow-up hello from %s: %s", conn.RemoteAddr(), describeClientHello(hello))
		} else if len(firstPacket) > 0 {
			log.Printf("mainline payload after direct probe from %s: %d bytes", conn.RemoteAddr(), len(firstPacket))
		}
	}

	if hello != nil {
		switch hello.GetType() {
		case sessionproto.ClientHelloType_CLIENT_HELLO_TYPE_ROOM_EXCHANGE:
			return handleRoomExchange(conn, hello)
		case sessionproto.ClientHelloType_CLIENT_HELLO_TYPE_PROVISION:
			return handleProvision(conn, hello)
		case sessionproto.ClientHelloType_CLIENT_HELLO_TYPE_SESSION:
			if mode == sessionproto.ModeMainline {
				selectedTransport, supportedTransports, _ := selectTransportForHello(mode, backends, hello)
				log.Printf(
					"protobuf mu session rejected for %s: server session mode is mainline",
					conn.RemoteAddr(),
				)
				return writeMuxSessionHelloResponse(
					conn,
					hello.GetVersion(),
					false,
					"server session mode is mainline",
					true,
					selectedTransport,
					supportedTransports,
					wrappedSession,
				)
			}
			selectedTransport, supportedTransports, errorText := selectTransportForHello(mode, backends, hello)
			if errorText != "" {
				log.Printf(
					"protobuf mu session rejected for %s: %s",
					conn.RemoteAddr(),
					errorText,
				)
				return writeMuxSessionHelloResponse(
					conn,
					hello.GetVersion(),
					false,
					errorText,
					true,
					selectedTransport,
					supportedTransports,
					wrappedSession,
				)
			}
			return runMuStream(ctx, conn, manager, backends.udpConnect, hello, wrappedSession, wrapPol, wrapListener)
		case sessionproto.ClientHelloType_CLIENT_HELLO_TYPE_PROBE:
			if mode == sessionproto.ModeMu {
				log.Printf("protobuf probe without session hello from %s in mu mode", conn.RemoteAddr())
				return fmt.Errorf("expected mu session hello after probe")
			}
		default:
			if mode == sessionproto.ModeMu {
				log.Printf("protobuf unsupported hello type from %s: %s", conn.RemoteAddr(), hello.GetType())
				return fmt.Errorf("unsupported client hello type: %s", hello.GetType())
			}
		}
	}

	if mode == sessionproto.ModeMu {
		log.Printf("protobuf mu hello missing from %s", conn.RemoteAddr())
		return fmt.Errorf("expected mu hello")
	}
	if !backends.supportsDatagram() {
		return fmt.Errorf("server datagram transport is unavailable")
	}
	log.Printf("switching %s to mainline data path", conn.RemoteAddr())
	return runLegacyStream(ctx, conn, backends.udpConnect, firstPacket, mode, backends)
}

func main() {
	opts, exitCode := parseServerOptions(os.Args[1:], filepath.Base(os.Args[0]), os.Stdout, os.Stderr)
	if exitCode != 0 && exitCode != -1 {
		os.Exit(exitCode)
	}
	if exitCode == 0 {
		os.Exit(0)
	}

	log.Printf("WINGS V VK TURN PROXY server %s starting", relayVersion)

	// On first run, snapshot the effective flags into the config file so the unit
	// can later drop them and rely on the file. Never overwrites an existing file.
	migrateFlagsToConfig(serverOptionsToConfigLines(opts))

	backends, err := resolveServerBackends(opts.connect, opts.udpConnect, opts.tcpConnect, opts.vlessMode)
	if err != nil {
		log.Panicf("invalid backend flags: %v", err)
	}

	wbStreamPool := newWbStreamSessionPool(backends.udpConnect)
	wbStreamPool.SetServerDisplayName(opts.wbStreamDisplayName)
	defer wbStreamPool.Close()
	SetRoomExchangeSink(wbStreamPool.HandleExchange)
	if opts.wbStreamRoomID != "" {
		for _, roomID := range strings.Split(opts.wbStreamRoomID, ",") {
			trimmed := strings.TrimSpace(roomID)
			if trimmed == "" {
				continue
			}
			if err := wbStreamPool.PreJoin(trimmed, opts.wbStreamE2ESecret); err != nil {
				log.Fatalf("wb-stream pre-join %q: %v", trimmed, err)
			}
		}
	}

	// peers is hoisted so the panel-provision block below can mint peers locally
	// on the own-wg path (provision-locally). nil when the management API is off.
	var peers *peerstore.Store
	if opts.grpcListen != "" {
		var applier wgapply.Applier = wgapply.Noop{}
		if opts.wgApply {
			wc, wcErr := wgapply.NewWGCtrl()
			if wcErr != nil {
				log.Fatalf("wg apply: %v", wcErr)
			}
			applier = wc
			defer func() { _ = wc.Close() }()
		}
		var perr error
		peers, perr = peerstore.New(opts.wgTunnelCIDR, opts.wgInterface, opts.wgKeyFile, applier)
		if perr != nil {
			log.Fatalf("relay peerstore: %v", perr)
		}
		if opts.wgApply {
			if err := applier.EnsureInterface(opts.wgInterface, peers.ServerPrivateKey(), opts.wgListenPort, opts.wgAddress); err != nil {
				log.Fatalf("wg ensure interface: %v", err)
			}
			log.Printf("WireGuard interface %s up on port %d", opts.wgInterface, opts.wgListenPort)
		}
		var grpcCreds credentials.TransportCredentials
		switch {
		case opts.grpcToken != "":
			// The token encrypts the channel with AES-256-GCM and needs no
			// handshake, so it authenticates AND avoids the TLS cert-chain that a
			// reduced-MTU client (k8s pod) cannot receive. Preferred over certs.
			grpcCreds = tokenaead.Server(opts.grpcToken)
			log.Printf("Relay management API: token-derived AES-256-GCM transport (no TLS)")
		case opts.grpcCert != "" && opts.grpcKey != "":
			tlsCreds, credErr := credentials.NewServerTLSFromFile(opts.grpcCert, opts.grpcKey)
			if credErr != nil {
				log.Fatalf("relay grpc tls: %v", credErr)
			}
			grpcCreds = tlsCreds
			log.Printf("Relay management API TLS enabled")
		default:
			log.Printf("Relay management API serving without TLS (token only)")
		}
		grpcServer := relaygrpc.NewServer(relaygrpc.Options{
			Store:    peers,
			Version:  relayVersion,
			Token:    opts.grpcToken,
			Creds:    grpcCreds,
			Flows:    flowRegistry{},
			Listen:   opts.listen,
			Sessions: func() uint64 { return uint64(serverUI.FlowStats().ActiveSessions) },
		})
		grpcLis, err := net.Listen("tcp", opts.grpcListen)
		if err != nil {
			log.Fatalf("relay grpc listen %s: %v", opts.grpcListen, err)
		}
		go func() {
			log.Printf("Relay management API on %s", opts.grpcListen)
			if serveErr := grpcServer.Serve(grpcLis); serveErr != nil {
				log.Printf("relay grpc serve: %v", serveErr)
			}
		}()
		defer grpcServer.GracefulStop()
	}

	var usagePoll usageResolver
	if opts.panelGRPC != "" {
		var pcOpts []panelclient.Option
		switch {
		case opts.panelCAPin != "":
			pin, pinErr := pintls.ParsePin(opts.panelCAPin)
			if pinErr != nil {
				log.Fatalf("invalid -panel-ca-pin: %v", pinErr)
			}
			pcOpts = append(pcOpts, panelclient.WithTransportCredentials(credentials.NewTLS(pintls.ClientConfig(pin))))
		case opts.panelInsecure:
			pcOpts = append(pcOpts, panelclient.WithInsecure())
		}
		pc := panelclient.New(opts.panelGRPC, opts.grpcToken, pcOpts...)
		SetProvisionResolver(pc, opts.nodeID, peers)
		usagePoll = pc
		log.Printf("DTLS PROVISION enabled via panel %s (node %s)", opts.panelGRPC, opts.nodeID)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	// Keep the managed-client traffic-limit cache fresh so mu heartbeats can echo
	// used/remaining to the app.
	if usagePoll != nil {
		startClientUsagePoller(ctx, usagePoll, opts.nodeID)
	}
	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, syscall.SIGTERM, syscall.SIGINT)
	go func() {
		<-signalChan
		log.Printf("Terminating...\n")
		cancel()
		<-signalChan
		log.Fatalf("Exit...\n")
	}()

	mode, err := sessionproto.ParseMode(opts.sessionMode)
	if err != nil {
		log.Panicf("invalid session mode: %v", err)
	}
	if mode == sessionproto.ModeMu && !backends.supportsDatagram() {
		log.Panicf("session-mode=mu requires -udp-connect")
	}
	modeLabel := string(mode)
	switch {
	case backends.supportsDatagram() && backends.supportsTCP():
		modeLabel += "+datagram/tcp"
	case backends.supportsTCP():
		modeLabel += "+tcp"
	default:
		modeLabel += "+datagram"
	}
	serverUI = newServerTUI(opts.listen, backends.describe(), modeLabel, opts.tuiMode)
	defer serverUI.Close()
	log.SetOutput(serverUI.logWriter())

	addr, err := net.ResolveUDPAddr("udp", opts.listen)
	if err != nil {
		panic(err)
	}

	certificate, genErr := selfsign.GenerateSelfSigned()
	if genErr != nil {
		panic(genErr)
	}

	dtlsOpts := []dtls.ServerOption{
		dtls.WithCertificates([]tls.Certificate{certificate}...),
		dtls.WithExtendedMasterSecret(dtls.RequireExtendedMasterSecret),
		dtls.WithCipherSuites(dtls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256),
		dtls.WithConnectionIDGenerator(dtls.RandomCIDGenerator(8)),
	}

	wrapPol, err := resolveServerWrapPolicy(opts.wrapMode, opts.wrapCipher, opts.wrapKeyHex, opts.wrapAcceptClientKeys)
	if err != nil {
		panic(err)
	}
	var (
		listener     net.Listener
		wrapListener *wrap.Listener
	)
	if wrapPol.enabled {
		desc := "in-band"
		if wrapPol.presetKey != nil {
			desc = "preset-key"
		}
		log.Printf("WRAP listener active (mode=on, %s, ciphers=%s)", desc, opts.wrapCipher)
		inner, listenErr := pionudp.Listen("udp", addr)
		if listenErr != nil {
			panic(listenErr)
		}
		wrapListener = wrap.NewListener(dtlsnet.PacketListenerFromListener(inner))
		listener, err = dtls.NewListenerWithOptions(wrapListener, dtlsOpts...)
	} else {
		listener, err = dtls.ListenWithOptions("udp", addr, dtlsOpts...)
	}
	if err != nil {
		panic(err)
	}
	context.AfterFunc(ctx, func() {
		if closeErr := listener.Close(); closeErr != nil {
			log.Printf("failed to close listener: %s", closeErr)
		}
	})

	manager := &SessionManager{
		Sessions: make(map[string]*UserSession),
	}

	log.Printf("Listening on %s, session mode=%s, backends=%s", opts.listen, mode, backends.describe())

	var wg sync.WaitGroup
	for {
		select {
		case <-ctx.Done():
			wg.Wait()
			return
		default:
		}

		conn, err := listener.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				wg.Wait()
				return
			default:
				log.Println(err)
				continue
			}
		}

		wg.Add(1)
		go func(conn net.Conn) {
			defer wg.Done()
			defer func() {
				if closeErr := conn.Close(); closeErr != nil {
					log.Printf("failed to close incoming connection: %s", closeErr)
				}
			}()

			log.Printf("Connection from %s", conn.RemoteAddr())
			if wrapListener != nil {
				defer wrapListener.Forget(conn.RemoteAddr())
			}
			if err := handleConnection(ctx, conn, manager, backends, mode, wrapPol, wrapListener); err != nil {
				log.Printf("Connection closed: %s (%v)", conn.RemoteAddr(), err)
			} else {
				log.Printf("Connection closed: %s", conn.RemoteAddr())
			}
		}(conn)
	}
}
