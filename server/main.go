package main

import (
	"context"
	"crypto/tls"
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/cacggghp/vk-turn-proxy/sessionproto"
	"github.com/pion/dtls/v3"
	"github.com/pion/dtls/v3/pkg/crypto/selfsign"
)

const initialNegotiationTimeout = 750 * time.Millisecond

var serverUI *serverTUI

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

func readInitialHelloOrLegacy(conn net.Conn, mode sessionproto.Mode) (*sessionproto.ClientHello, []byte, error) {
	buf := make([]byte, 1600)
	if err := conn.SetReadDeadline(time.Now().Add(initialNegotiationTimeout)); err != nil {
		return nil, nil, err
	}
	n, err := conn.Read(buf)
	if clearErr := conn.SetReadDeadline(time.Time{}); clearErr != nil {
		return nil, nil, clearErr
	}
	if err != nil {
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			if mode == sessionproto.ModeMux {
				return nil, nil, fmt.Errorf("timed out waiting for mux hello")
			}
			return nil, nil, nil
		}
		return nil, nil, err
	}

	payload := append([]byte(nil), buf[:n]...)
	hello, parseErr := sessionproto.ParseClientHelloMessage(payload)
	if parseErr != nil {
		if mode == sessionproto.ModeMux {
			return nil, nil, fmt.Errorf("invalid mux hello: %w", parseErr)
		}
		return nil, payload, nil
	}
	if validateErr := validateClientHelloForVersion(hello); validateErr != nil {
		if mode == sessionproto.ModeMux {
			return nil, nil, fmt.Errorf("invalid mux hello: %w", validateErr)
		}
		return nil, payload, nil
	}
	return hello, nil, nil
}

func runLegacyStream(ctx context.Context, conn net.Conn, connectAddr string, firstPacket []byte, mode sessionproto.Mode) error {
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
		if handled, controlErr := handleMainlineControlPacket(conn, firstPacket, mode); handled {
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
			if handled, controlErr := handleMainlineControlPacket(conn, buf[:n], mode); handled {
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

func runMuxStream(ctx context.Context, conn net.Conn, manager *SessionManager, connectAddr string, hello *sessionproto.ClientHello) error {
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

	if err := writeServerHelloForVersion(conn, hello.GetVersion(), true, "", true); err != nil {
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

func handleConnection(ctx context.Context, conn net.Conn, manager *SessionManager, connectAddr string, mode sessionproto.Mode) error {
	dtlsConn, ok := conn.(*dtls.Conn)
	if !ok {
		return fmt.Errorf("unexpected connection type")
	}

	handshakeCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	if err := dtlsConn.HandshakeContext(handshakeCtx); err != nil {
		return err
	}

	hello, firstPacket, err := readInitialHelloOrLegacy(conn, mode)
	if err != nil {
		return err
	}
	if hello != nil {
		log.Printf("protobuf initial hello from %s: %s", conn.RemoteAddr(), describeClientHello(hello))
	} else if len(firstPacket) > 0 {
		log.Printf("mainline legacy payload from %s: %d bytes", conn.RemoteAddr(), len(firstPacket))
	} else {
		log.Printf("no initial protobuf hello from %s", conn.RemoteAddr())
	}

	for hello != nil && hello.GetType() == sessionproto.ClientHelloType_CLIENT_HELLO_TYPE_PROBE {
		muxSupported := mode != sessionproto.ModeMainline
		errorText := ""
		if !muxSupported {
			errorText = "server session mode is mainline"
		}
		log.Printf(
			"protobuf direct probe from %s: version=%d mux_supported=%t error=%q",
			conn.RemoteAddr(),
			hello.GetVersion(),
			muxSupported,
			errorText,
		)
		if err := writeServerHelloForVersion(conn, hello.GetVersion(), muxSupported, errorText, true); err != nil {
			return err
		}
		hello, firstPacket, err = readInitialHelloOrLegacy(conn, mode)
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
				log.Printf(
					"protobuf mux session rejected for %s: server session mode is mainline",
					conn.RemoteAddr(),
				)
				return writeServerHelloForVersion(conn, hello.GetVersion(), false, "server session mode is mainline", true)
			}
			return runMuxStream(ctx, conn, manager, connectAddr, hello)
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
	log.Printf("switching %s to mainline data path", conn.RemoteAddr())
	return runLegacyStream(ctx, conn, connectAddr, firstPacket, mode)
}

func main() {
	listen := flag.String("listen", "0.0.0.0:56000", "listen on ip:port")
	connect := flag.String("connect", "", "connect to ip:port")
	sessionModeFlag := flag.String("session-mode", string(sessionproto.ModeAuto), "TURN session mode: mainline|mux|auto")
	tuiModeFlag := flag.String("tui", "auto", "server TUI mode: auto|on|off")
	flag.Parse()

	mode, err := sessionproto.ParseMode(*sessionModeFlag)
	if err != nil {
		log.Panicf("invalid session mode: %v", err)
	}
	serverUI = newServerTUI(*listen, *connect, string(mode), *tuiModeFlag)
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
	if len(*connect) == 0 {
		log.Panicf("server address is required")
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

	log.Printf("Listening on %s, forwarding to %s, session mode=%s", *listen, *connect, mode)

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
			if err := handleConnection(ctx, conn, manager, *connect, mode); err != nil {
				log.Printf("Connection closed: %s (%v)", conn.RemoteAddr(), err)
			} else {
				log.Printf("Connection closed: %s", conn.RemoteAddr())
			}
		}(conn)
	}
}
