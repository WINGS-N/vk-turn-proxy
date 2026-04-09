package main

import (
	"context"
	"crypto/tls"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/cacggghp/vk-turn-proxy/sessionproto"
	sessionv3 "github.com/cacggghp/vk-turn-proxy/sessionproto/v3"
	"github.com/pion/dtls/v3"
	"github.com/pion/dtls/v3/pkg/crypto/selfsign"
)

const initialNegotiationTimeout = 750 * time.Millisecond

var serverUI *serverTUI

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

func allowsMux(mode sessionproto.Mode) bool {
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
	if helloType != sessionproto.ClientHelloType_CLIENT_HELLO_TYPE_SESSION && mode != sessionproto.ModeMux && backends.supportsTCP() {
		supported = append(supported, sessionproto.TransportMode_TRANSPORT_MODE_TCP)
	}
	return sessionproto.NormalizeSupportedTransports(supported)
}

func requestedTransportForHello(hello *sessionproto.ClientHello) sessionproto.TransportMode {
	if hello == nil {
		return sessionproto.TransportMode_TRANSPORT_MODE_DATAGRAM
	}
	requested := hello.GetRequestedTransport()
	if hello.GetVersion() < sessionv3.ProtocolVersion || requested == sessionproto.TransportMode_TRANSPORT_MODE_UNSPECIFIED {
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

func selectTransportForHello(mode sessionproto.Mode, backends transportBackends, hello *sessionproto.ClientHello) (sessionproto.TransportMode, []sessionproto.TransportMode, string) {
	supported := supportedTransportsForHello(mode, backends, hello)
	requested := requestedTransportForHello(hello)

	switch requested {
	case sessionproto.TransportMode_TRANSPORT_MODE_TCP:
		if hello != nil && hello.GetType() == sessionproto.ClientHelloType_CLIENT_HELLO_TYPE_SESSION {
			return firstSupportedTransport(supported), supported, "mux session mode does not support tcp transport"
		}
		if mode == sessionproto.ModeMux {
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
	BackendConn net.Conn
	Lock        sync.RWMutex
	Ctx         context.Context
	Cancel      context.CancelFunc
	Manager     *SessionManager
	DebugRx     atomic.Uint32
	DebugTx     atomic.Uint32
}

type SessionManager struct {
	Sessions map[string]*UserSession
	Lock     sync.RWMutex
}

func (s *SessionManager) GetOrCreate(ctx context.Context, id string, connectAddr string) (*UserSession, error) {
	s.Lock.Lock()
	defer s.Lock.Unlock()

	if session, ok := s.Sessions[id]; ok {
		return session, nil
	}

	backendConn, err := net.Dial("udp", connectAddr)
	if err != nil {
		return nil, err
	}

	sessionCtx, cancel := context.WithCancel(ctx)
	session := &UserSession{
		ID:          id,
		Conns:       make([]streamEntry, 0),
		BackendConn: backendConn,
		Manager:     s,
		Ctx:         sessionCtx,
		Cancel:      cancel,
	}
	s.Sessions[id] = session
	if serverUI != nil {
		serverUI.registerSession(id)
	}
	log.Printf(
		"Session %s backend connected: local=%s remote=%s",
		id,
		backendConn.LocalAddr(),
		backendConn.RemoteAddr(),
	)
	go session.backendReaderLoop()

	return session, nil
}

func (s *UserSession) backendReaderLoop() {
	defer s.Cleanup()
	buf := make([]byte, 1600)
	var lastUsed uint32

	for {
		select {
		case <-s.Ctx.Done():
			return
		default:
		}

		if err := s.BackendConn.SetReadDeadline(time.Now().Add(5 * time.Minute)); err != nil {
			log.Printf("Session %s backend deadline error: %v", s.ID, err)
			return
		}
		n, err := s.BackendConn.Read(buf)
		if err != nil {
			log.Printf("Session %s backend read error: %v", s.ID, err)
			return
		}

		s.Lock.RLock()
		nConns := uint32(len(s.Conns))
		if nConns == 0 {
			s.Lock.RUnlock()
			continue
		}

		lastUsed = (lastUsed + 1) % nConns
		entry := s.Conns[lastUsed]
		conn := entry.conn
		s.Lock.RUnlock()

		if err := conn.SetWriteDeadline(time.Now().Add(10 * time.Second)); err != nil {
			log.Printf("Session %s DTLS write deadline error: %v", s.ID, err)
			if closeErr := conn.Close(); closeErr != nil {
				log.Printf("Session %s failed to close DTLS connection: %v", s.ID, closeErr)
			}
			continue
		}
		if _, err = conn.Write(buf[:n]); err != nil {
			log.Printf("Session %s DTLS write error: %v", s.ID, err)
			if closeErr := conn.Close(); closeErr != nil {
				log.Printf("Session %s failed to close DTLS connection: %v", s.ID, closeErr)
			}
			continue
		}
		if serverUI != nil {
			serverUI.addStreamTx(entry.key, entry.clientIP, n)
		}
	}
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
	defer s.Lock.Unlock()

	for i, entry := range s.Conns {
		if entry.id == id && entry.conn == conn {
			s.Conns = append(s.Conns[:i], s.Conns[i+1:]...)
			break
		}
	}
}

func (s *UserSession) ActiveConnCount() uint32 {
	s.Lock.RLock()
	defer s.Lock.RUnlock()
	return uint32(len(s.Conns))
}

func (s *UserSession) Cleanup() {
	s.Cancel()
	_ = s.BackendConn.Close()

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
			if mode == sessionproto.ModeMux {
				return nil, nil, false, fmt.Errorf("timed out waiting for mux hello")
			}
			return nil, nil, false, nil
		}
		return nil, nil, false, err
	}

	payload := append([]byte(nil), buf[:n]...)
	if sessionPayload, ok := sessionproto.ParseControlSessionRequest(payload); ok {
		hello, parseErr := sessionproto.ParseClientHelloMessage(sessionPayload)
		if parseErr != nil {
			return nil, nil, false, fmt.Errorf("invalid mux hello: %w", parseErr)
		}
		if validateErr := validateClientHelloForVersion(hello); validateErr != nil {
			return nil, nil, false, fmt.Errorf("invalid mux hello: %w", validateErr)
		}
		return hello, nil, true, nil
	}
	hello, parseErr := sessionproto.ParseClientHelloMessage(payload)
	if parseErr != nil {
		if mode == sessionproto.ModeMux {
			return nil, nil, false, fmt.Errorf("invalid mux hello: %w", parseErr)
		}
		return nil, payload, false, nil
	}
	if validateErr := validateClientHelloForVersion(hello); validateErr != nil {
		if mode == sessionproto.ModeMux {
			return nil, nil, false, fmt.Errorf("invalid mux hello: %w", validateErr)
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
		"mainline legacy payload from %s: %d bytes, prefix=%x",
		conn.RemoteAddr(),
		len(firstPacket),
		firstPacket[:prefixLen],
	)
}

func runLegacyStream(ctx context.Context, conn net.Conn, connectAddr string, firstPacket []byte, mode sessionproto.Mode, backends transportBackends) error {
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
			if handled, controlErr := handleControlHeartbeatPacket(conn, buf[:n], streamKey, 1); handled {
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
	payload, err := buildServerHelloForVersion(
		version,
		muxSupported,
		errorText,
		controlHeartbeatSupported,
		selectedTransport,
		supportedTransports,
	)
	if err != nil {
		return err
	}
	if wrappedSession && version >= sessionv3.ProtocolVersion {
		return writeRawPacket(conn, sessionproto.BuildControlSessionResponse(payload))
	}
	return writeRawPacket(conn, payload)
}

func runMuxStream(ctx context.Context, conn net.Conn, manager *SessionManager, connectAddr string, hello *sessionproto.ClientHello, wrappedSession bool) error {
	sessionID := hex.EncodeToString(hello.GetSessionId())
	streamID := byte(hello.GetStreamId())
	clientIP := clientIPFromAddr(conn.RemoteAddr())
	streamKey := ""
	if serverUI != nil {
		streamKey = serverUI.nextStreamKey("mux")
		serverUI.registerStream(
			streamKey,
			fmt.Sprintf("mux/v%d", hello.GetVersion()),
			hello.GetVersion(),
			conn.RemoteAddr().String(),
			clientIP,
			sessionID,
			streamID,
		)
		defer serverUI.unregisterStream(streamKey)
	}
	log.Printf(
		"protobuf mux session hello from %s: %s",
		conn.RemoteAddr(),
		describeClientHello(hello),
	)

	session, err := manager.GetOrCreate(ctx, sessionID, connectAddr)
	if err != nil {
		return err
	}

	session.AddConn(streamID, streamKey, clientIP, conn)
	defer session.RemoveConn(streamID, conn)

	if err := writeMuxSessionHelloResponse(
		conn,
		hello.GetVersion(),
		true,
		"",
		true,
		sessionproto.TransportMode_TRANSPORT_MODE_DATAGRAM,
		[]sessionproto.TransportMode{sessionproto.TransportMode_TRANSPORT_MODE_DATAGRAM},
		wrappedSession,
	); err != nil {
		return err
	}

	log.Printf("New stream %d for session %s from %s", streamID, sessionID, conn.RemoteAddr())

	buf := make([]byte, 1600)
	for {
		if err := conn.SetReadDeadline(time.Now().Add(5 * time.Minute)); err != nil {
			return err
		}
		n, err := conn.Read(buf)
		if err != nil {
			return err
		}
		if handled, controlErr := handleControlHeartbeatPacket(conn, buf[:n], streamKey, session.ActiveConnCount()); handled {
			if controlErr != nil {
				return controlErr
			}
			continue
		}

		if err := session.BackendConn.SetWriteDeadline(time.Now().Add(5 * time.Second)); err != nil {
			return err
		}
		if _, err = session.BackendConn.Write(buf[:n]); err != nil {
			return err
		}
		if serverUI != nil {
			serverUI.addStreamRx(streamKey, clientIP, n)
		}
	}
}

func handleConnection(ctx context.Context, conn net.Conn, manager *SessionManager, backends transportBackends, mode sessionproto.Mode) error {
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

	for hello != nil && hello.GetType() == sessionproto.ClientHelloType_CLIENT_HELLO_TYPE_PROBE {
		selectedTransport, supportedTransports, errorText := selectTransportForHello(mode, backends, hello)
		muxSupported := allowsMux(mode) && errorText == ""
		log.Printf(
			"protobuf direct probe from %s: version=%d requested_transport=%s selected_transport=%s mux_supported=%t error=%q",
			conn.RemoteAddr(),
			hello.GetVersion(),
			requestedTransportForHello(hello),
			selectedTransport,
			muxSupported,
			errorText,
		)
		if err := writeServerHelloForVersion(
			conn,
			hello.GetVersion(),
			muxSupported,
			errorText,
			true,
			selectedTransport,
			supportedTransports,
		); err != nil {
			return err
		}
		if errorText != "" {
			return fmt.Errorf("%s", errorText)
		}
		if selectedTransport == sessionproto.TransportMode_TRANSPORT_MODE_TCP {
			log.Printf("switching %s to tcp data path", conn.RemoteAddr())
			return handleTCPConnection(ctx, dtlsConn, backends.tcpConnect)
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
		case sessionproto.ClientHelloType_CLIENT_HELLO_TYPE_SESSION:
			if mode == sessionproto.ModeMainline {
				selectedTransport, supportedTransports, _ := selectTransportForHello(mode, backends, hello)
				log.Printf(
					"protobuf mux session rejected for %s: server session mode is mainline",
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
					"protobuf mux session rejected for %s: %s",
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
			return runMuxStream(ctx, conn, manager, backends.udpConnect, hello, wrappedSession)
		case sessionproto.ClientHelloType_CLIENT_HELLO_TYPE_PROBE:
			if mode == sessionproto.ModeMux {
				log.Printf("protobuf probe without session hello from %s in mux mode", conn.RemoteAddr())
				return fmt.Errorf("expected mux session hello after probe")
			}
		default:
			if mode == sessionproto.ModeMux {
				log.Printf("protobuf unsupported hello type from %s: %s", conn.RemoteAddr(), hello.GetType())
				return fmt.Errorf("unsupported client hello type: %s", hello.GetType())
			}
		}
	}

	if mode == sessionproto.ModeMux {
		log.Printf("protobuf mux hello missing from %s", conn.RemoteAddr())
		return fmt.Errorf("expected mux hello")
	}
	if !backends.supportsDatagram() {
		return fmt.Errorf("server datagram transport is unavailable")
	}
	log.Printf("switching %s to mainline data path", conn.RemoteAddr())
	return runLegacyStream(ctx, conn, backends.udpConnect, firstPacket, mode, backends)
}

func main() {
	listen := flag.String("listen", "0.0.0.0:56000", "listen on ip:port")
	connect := flag.String("connect", "", "deprecated alias for -udp-connect (or -tcp-connect when -vless is set)")
	udpConnectFlag := flag.String("udp-connect", "", "UDP backend for datagram transport")
	tcpConnectFlag := flag.String("tcp-connect", "", "TCP backend for tcp transport")
	vlessModeFlag := flag.Bool("vless", false, "deprecated alias: treat legacy -connect as -tcp-connect")
	sessionModeFlag := flag.String("session-mode", string(sessionproto.ModeAuto), "TURN session mode: mainline|mux|auto")
	tuiModeFlag := flag.String("tui", "auto", "server TUI mode: auto|on|off")
	flag.Parse()

	mode, err := sessionproto.ParseMode(*sessionModeFlag)
	if err != nil {
		log.Panicf("invalid session mode: %v", err)
	}
	backends, err := resolveServerBackends(*connect, *udpConnectFlag, *tcpConnectFlag, *vlessModeFlag)
	if err != nil {
		log.Panicf("invalid backend flags: %v", err)
	}
	if mode == sessionproto.ModeMux && !backends.supportsDatagram() {
		log.Panicf("session-mode=mux requires -udp-connect")
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
	serverUI = newServerTUI(*listen, backends.describe(), modeLabel, *tuiModeFlag)
	defer serverUI.Close()
	log.SetOutput(serverUI.logWriter())

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, syscall.SIGTERM, syscall.SIGINT)
	go func() {
		<-signalChan
		log.Printf("Terminating...\n")
		cancel()
		<-signalChan
		log.Fatalf("Exit...\n")
	}()

	addr, err := net.ResolveUDPAddr("udp", *listen)
	if err != nil {
		panic(err)
	}

	certificate, genErr := selfsign.GenerateSelfSigned()
	if genErr != nil {
		panic(genErr)
	}

	config := &dtls.Config{
		Certificates:          []tls.Certificate{certificate},
		ExtendedMasterSecret:  dtls.RequireExtendedMasterSecret,
		CipherSuites:          []dtls.CipherSuiteID{dtls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256},
		ConnectionIDGenerator: dtls.RandomCIDGenerator(8),
	}

	listener, err := dtls.Listen("udp", addr, config)
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

	log.Printf("Listening on %s, session mode=%s, backends=%s", *listen, mode, backends.describe())

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
			if err := handleConnection(ctx, conn, manager, backends, mode); err != nil {
				log.Printf("Connection closed: %s (%v)", conn.RemoteAddr(), err)
			} else {
				log.Printf("Connection closed: %s", conn.RemoteAddr())
			}
		}(conn)
	}
}
