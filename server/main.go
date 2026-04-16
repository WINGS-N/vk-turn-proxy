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
	"syscall"
	"time"

	"github.com/cacggghp/vk-turn-proxy/internal/controlpath"
	"github.com/cacggghp/vk-turn-proxy/sessionproto"
	sessionmuv1 "github.com/cacggghp/vk-turn-proxy/sessionproto/mu/v1"
	"github.com/cacggghp/vk-turn-proxy/tcputil"
	"github.com/pion/dtls/v3"
	"github.com/pion/dtls/v3/pkg/crypto/selfsign"
	"github.com/xtaci/smux"
)

const initialNegotiationTimeout = 750 * time.Millisecond

var serverUI *serverTUI

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
	if wrappedSession && version >= sessionmuv1.ProtocolVersion {
		return writeRawPacket(conn, sessionproto.BuildControlSessionResponse(payload))
	}
	return writeRawPacket(conn, payload)
}

func runMuStream(ctx context.Context, conn net.Conn, manager *SessionManager, connectAddr string, hello *sessionproto.ClientHello, wrappedSession bool) error {
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
			if handled, controlErr := handleControlHeartbeatPacket(conn, buf[:n], streamKey, controlpath.HeartbeatMeta{
				SessionMode: string(sessionproto.ModeMu),
				ControlPath: controlpath.PathTurnDTLS,
				Provider:    controlpath.ProviderTurn,
				Transport:   sessionproto.TransportMode_TRANSPORT_MODE_DATAGRAM,
				ActiveFlows: session.ActiveConnCount(),
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

func handleConnection(
	ctx context.Context,
	conn net.Conn,
	manager *SessionManager,
	backends transportBackends,
	mode sessionproto.Mode,
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

	for hello != nil && hello.GetType() == sessionproto.ClientHelloType_CLIENT_HELLO_TYPE_PROBE {
		selectedTransport, supportedTransports, errorText := selectTransportForHello(mode, backends, hello)
		muSupported := allowsMu(mode) && errorText == ""
		log.Printf(
			"protobuf direct probe from %s: version=%d requested_transport=%s selected_transport=%s mu_supported=%t error=%q",
			conn.RemoteAddr(),
			hello.GetVersion(),
			requestedTransportForHello(hello),
			selectedTransport,
			muSupported,
			errorText,
		)
		if err := writeServerHelloForVersion(
			conn,
			hello.GetVersion(),
			muSupported,
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
			return runMuStream(ctx, conn, manager, backends.udpConnect, hello, wrappedSession)
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

	backends, err := resolveServerBackends(opts.connect, opts.udpConnect, opts.tcpConnect, opts.vlessMode)
	if err != nil {
		log.Panicf("invalid backend flags: %v", err)
	}

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
			if err := handleConnection(ctx, conn, manager, backends, mode); err != nil {
				log.Printf("Connection closed: %s (%v)", conn.RemoteAddr(), err)
			} else {
				log.Printf("Connection closed: %s", conn.RemoteAddr())
			}
		}(conn)
	}
}

// handleUDPConnection forwards DTLS packets to a UDP backend (WireGuard).
func handleUDPConnection(ctx context.Context, conn net.Conn, connectAddr string) {
	serverConn, err := net.Dial("udp", connectAddr)
	if err != nil {
		log.Println(err)
		return
	}
	defer func() {
		if err = serverConn.Close(); err != nil {
			log.Printf("failed to close outgoing connection: %s", err)
		}
	}()

	var wg sync.WaitGroup
	wg.Add(2)
	ctx2, cancel2 := context.WithCancel(ctx)
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
			if err1 := conn.SetReadDeadline(time.Now().Add(time.Minute * 30)); err1 != nil {
				log.Printf("Failed: %s", err1)
				return
			}
			n, err1 := conn.Read(buf)
			if err1 != nil {
				log.Printf("Failed: %s", err1)
				return
			}

			if err1 = serverConn.SetWriteDeadline(time.Now().Add(time.Minute * 30)); err1 != nil {
				log.Printf("Failed: %s", err1)
				return
			}
			_, err1 = serverConn.Write(buf[:n])
			if err1 != nil {
				log.Printf("Failed: %s", err1)
				return
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
			if err1 := serverConn.SetReadDeadline(time.Now().Add(time.Minute * 30)); err1 != nil {
				log.Printf("Failed: %s", err1)
				return
			}
			n, err1 := serverConn.Read(buf)
			if err1 != nil {
				log.Printf("Failed: %s", err1)
				return
			}

			if err1 = conn.SetWriteDeadline(time.Now().Add(time.Minute * 30)); err1 != nil {
				log.Printf("Failed: %s", err1)
				return
			}
			_, err1 = conn.Write(buf[:n])
			if err1 != nil {
				log.Printf("Failed: %s", err1)
				return
			}
		}
	}()
	wg.Wait()
}

// handleVLESSConnection creates a KCP+smux session over DTLS and forwards
// each smux stream as a TCP connection to the backend (Xray/VLESS).
func handleVLESSConnection(ctx context.Context, dtlsConn net.Conn, connectAddr string) {
	// 1. Create KCP session over DTLS
	kcpSess, err := tcputil.NewKCPOverDTLS(dtlsConn, true)
	if err != nil {
		log.Printf("KCP session error: %s", err)
		return
	}
	defer func() {
		if err := kcpSess.Close(); err != nil {
			log.Printf("failed to close KCP session: %v", err)
		}
	}()
	log.Printf("KCP session established (server)")

	// 2. Create smux server session over KCP
	smuxSess, err := smux.Server(kcpSess, tcputil.DefaultSmuxConfig())
	if err != nil {
		log.Printf("smux server error: %s", err)
		return
	}
	defer func() {
		if err := smuxSess.Close(); err != nil {
			log.Printf("failed to close smux session: %v", err)
		}
	}()
	log.Printf("smux session established (server)")

	// 3. Accept smux streams and forward to backend via TCP
	var wg sync.WaitGroup
	for {
		stream, err := smuxSess.AcceptStream()
		if err != nil {
			select {
			case <-ctx.Done():
			default:
				log.Printf("smux accept error: %s", err)
			}
			break
		}

		wg.Add(1)
		go func(s *smux.Stream) {
			defer wg.Done()

			defer func() {
				if err := s.Close(); err != nil && err != smux.ErrGoAway {
					log.Printf("failed to close smux stream: %v", err)
				}
			}()

			// Connect to backend (Xray/VLESS)
			backendConn, err := net.DialTimeout("tcp", connectAddr, 10*time.Second)
			if err != nil {
				log.Printf("backend dial error: %s", err)
				return
			}
			defer func() {
				if err := backendConn.Close(); err != nil {
					log.Printf("failed to close backend connection: %v", err)
				}
			}()

			// Bidirectional copy
			pipeConn(ctx, s, backendConn)
		}(stream)
	}
	wg.Wait()
}

// pipeConn copies data bidirectionally between two connections.
func pipeConn(ctx context.Context, c1, c2 net.Conn) {
	ctx2, cancel := context.WithCancel(ctx)
	defer cancel()

	context.AfterFunc(ctx2, func() {
		if err := c1.SetDeadline(time.Now()); err != nil {
			log.Printf("pipeConn: failed to set deadline c1: %v", err)
		}
		if err := c2.SetDeadline(time.Now()); err != nil {
			log.Printf("pipeConn: failed to set deadline c2: %v", err)
		}
	})

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		if _, err := io.Copy(c1, c2); err != nil {
			log.Printf("pipeConn: c1<-c2 copy error: %v", err)
		}
	}()

	go func() {
		defer wg.Done()
		if _, err := io.Copy(c2, c1); err != nil {
			log.Printf("pipeConn: c2<-c1 copy error: %v", err)
		}
	}()

	wg.Wait()

	// Reset deadlines
	_ = c1.SetDeadline(time.Time{})
	_ = c2.SetDeadline(time.Time{})
}
