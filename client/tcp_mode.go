package main

import (
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cacggghp/vk-turn-proxy/sessionproto"
	sessionmuv1 "github.com/cacggghp/vk-turn-proxy/sessionproto/mu/v1"
	"github.com/cacggghp/vk-turn-proxy/tcputil"
	"github.com/pion/logging"
	"github.com/pion/turn/v5"
	"github.com/xtaci/smux"
)

type relayPacketConn struct {
	relay net.PacketConn
	peer  net.Addr
}

func (relay *relayPacketConn) ReadFrom(buffer []byte) (int, net.Addr, error) {
	return relay.relay.ReadFrom(buffer)
}

func (relay *relayPacketConn) WriteTo(buffer []byte, _ net.Addr) (int, error) {
	return relay.relay.WriteTo(buffer, relay.peer)
}

func (relay *relayPacketConn) Close() error {
	return relay.relay.Close()
}

func (relay *relayPacketConn) LocalAddr() net.Addr {
	return relay.relay.LocalAddr()
}

func (relay *relayPacketConn) SetDeadline(deadline time.Time) error {
	return relay.relay.SetDeadline(deadline)
}

func (relay *relayPacketConn) SetReadDeadline(deadline time.Time) error {
	return relay.relay.SetReadDeadline(deadline)
}

func (relay *relayPacketConn) SetWriteDeadline(deadline time.Time) error {
	return relay.relay.SetWriteDeadline(deadline)
}

type tcpSessionPool struct {
	lock     sync.RWMutex
	sessions []*smux.Session
	counter  atomic.Uint64
}

func (pool *tcpSessionPool) add(session *smux.Session) {
	pool.lock.Lock()
	pool.sessions = append(pool.sessions, session)
	pool.lock.Unlock()
}

func (pool *tcpSessionPool) remove(session *smux.Session) {
	pool.lock.Lock()
	for idx, existing := range pool.sessions {
		if existing == session {
			pool.sessions = append(pool.sessions[:idx], pool.sessions[idx+1:]...)
			break
		}
	}
	pool.lock.Unlock()
}

func (pool *tcpSessionPool) pick() *smux.Session {
	pool.lock.RLock()
	defer pool.lock.RUnlock()
	if len(pool.sessions) == 0 {
		return nil
	}
	idx := pool.counter.Add(1) % uint64(len(pool.sessions))
	return pool.sessions[idx]
}

func (pool *tcpSessionPool) count() int {
	pool.lock.RLock()
	defer pool.lock.RUnlock()
	return len(pool.sessions)
}

func runTCPMode(ctx context.Context, turnConfig *turnParams, peer *net.UDPAddr, listenAddr string, sessionCount int) {
	sessionCount = max(1, sessionCount)
	pool := &tcpSessionPool{}

	var maintainers sync.WaitGroup
	for sessionID := 0; sessionID < sessionCount; sessionID++ {
		maintainers.Add(1)
		go func(id int) {
			defer maintainers.Done()
			select {
			case <-ctx.Done():
				return
			case <-time.After(time.Duration(id) * 300 * time.Millisecond):
			}
			maintainTCPSession(ctx, turnConfig, peer, id, pool)
		}(sessionID)
	}

	log.Printf("TCP mode: waiting for sessions to connect (total: %d)...", sessionCount)
	for {
		select {
		case <-ctx.Done():
			maintainers.Wait()
			return
		case <-time.After(100 * time.Millisecond):
		}
		if pool.count() > 0 {
			break
		}
	}

	listener, err := net.Listen("tcp", listenAddr)
	if err != nil {
		log.Panicf("TCP listen: %s", err)
	}
	context.AfterFunc(ctx, func() { _ = listener.Close() })
	log.Printf("TCP mode: listening on %s (round-robin across %d sessions)", listenAddr, sessionCount)

	var accepted sync.WaitGroup
	for {
		tcpConn, err := listener.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				accepted.Wait()
				maintainers.Wait()
				return
			default:
			}
			log.Printf("TCP accept error: %s", err)
			continue
		}

		session := pool.pick()
		if session == nil || session.IsClosed() {
			log.Printf("No active TCP sessions, rejecting TCP connection")
			_ = tcpConn.Close()
			continue
		}

		accepted.Add(1)
		go func(localConn net.Conn, smuxSession *smux.Session) {
			defer accepted.Done()
			defer func() { _ = localConn.Close() }()

			stream, err := smuxSession.OpenStream()
			if err != nil {
				log.Printf("smux open stream error: %s", err)
				return
			}
			defer func() { _ = stream.Close() }()

			pipeNetConns(ctx, localConn, stream)
		}(tcpConn, session)
	}
}

func maintainTCPSession(ctx context.Context, turnConfig *turnParams, peer *net.UDPAddr, sessionID int, pool *tcpSessionPool) {
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		smuxSession, cleanup, err := createTCPSmuxSession(ctx, turnConfig, peer)
		if err != nil {
			log.Printf("[tcp session %d] setup error: %s, retrying...", sessionID, err)
			select {
			case <-ctx.Done():
				return
			case <-time.After(3 * time.Second):
			}
			continue
		}

		pool.add(smuxSession)
		log.Printf("[tcp session %d] connected (active: %d)", sessionID, pool.count())

		for !smuxSession.IsClosed() {
			select {
			case <-ctx.Done():
				pool.remove(smuxSession)
				cleanup()
				return
			case <-time.After(1 * time.Second):
			}
		}

		pool.remove(smuxSession)
		cleanup()
		log.Printf("[tcp session %d] disconnected (active: %d), reconnecting...", sessionID, pool.count())

		select {
		case <-ctx.Done():
			return
		case <-time.After(2 * time.Second):
		}
	}
}

func createTCPSmuxSession(ctx context.Context, turnConfig *turnParams, peer *net.UDPAddr) (*smux.Session, func(), error) {
	cleanupFns := make([]func(), 0, 8)
	cleanupOnce := &sync.Once{}
	cleanup := func() {
		cleanupOnce.Do(func() {
			for idx := len(cleanupFns) - 1; idx >= 0; idx-- {
				cleanupFns[idx]()
			}
		})
	}

	user, pass, rawURL, err := turnConfig.getCreds(turnConfig.link)
	if err != nil {
		return nil, nil, fmt.Errorf("get TURN creds: %w", err)
	}
	emitProxyStatus("auth_ready")

	urlHost, urlPort, err := net.SplitHostPort(rawURL)
	if err != nil {
		return nil, nil, fmt.Errorf("parse TURN addr: %w", err)
	}
	if turnConfig.host != "" {
		urlHost = turnConfig.host
	}
	if turnConfig.port != "" {
		urlPort = turnConfig.port
	}
	turnServerAddr := net.JoinHostPort(urlHost, urlPort)
	turnServerUDPAddr, err := turnConfig.resolver.ResolveUDPAddr(ctx, turnServerAddr)
	if err != nil {
		return nil, nil, fmt.Errorf("resolve TURN addr: %w", err)
	}
	turnServerAddr = turnServerUDPAddr.String()

	var turnConn net.PacketConn
	dialer := turnConfig.resolver.dialer()
	dialCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	if turnConfig.udp {
		rawConn, err := dialer.DialContext(dialCtx, "udp", turnServerAddr)
		if err != nil {
			return nil, nil, fmt.Errorf("dial TURN (udp): %w", err)
		}
		conn, ok := rawConn.(*net.UDPConn)
		if !ok {
			_ = rawConn.Close()
			return nil, nil, fmt.Errorf("failed to cast protected UDP connection")
		}
		cleanupFns = append(cleanupFns, func() { _ = conn.Close() })
		turnConn = &connectedUDPConn{conn}
	} else {
		conn, err := dialer.DialContext(dialCtx, "tcp", turnServerAddr)
		if err != nil {
			return nil, nil, fmt.Errorf("dial TURN (tcp): %w", err)
		}
		cleanupFns = append(cleanupFns, func() { _ = conn.Close() })
		turnConn = turn.NewSTUNConn(conn)
	}

	var addrFamily turn.RequestedAddressFamily
	if peer.IP.To4() != nil {
		addrFamily = turn.RequestedAddressFamilyIPv4
	} else {
		addrFamily = turn.RequestedAddressFamilyIPv6
	}

	client, err := turn.NewClient(&turn.ClientConfig{
		STUNServerAddr:         turnServerAddr,
		TURNServerAddr:         turnServerAddr,
		Conn:                   turnConn,
		Net:                    newDirectNet(),
		Username:               user,
		Password:               pass,
		RequestedAddressFamily: addrFamily,
		LoggerFactory:          logging.NewDefaultLoggerFactory(),
	})
	if err != nil {
		cleanup()
		return nil, nil, fmt.Errorf("create TURN client: %w", err)
	}
	cleanupFns = append(cleanupFns, func() { client.Close() })
	if err = client.Listen(); err != nil {
		cleanup()
		return nil, nil, fmt.Errorf("TURN listen: %w", err)
	}

	relayConn, err := client.Allocate()
	if err != nil {
		cleanup()
		return nil, nil, fmt.Errorf("TURN allocate: %w", err)
	}
	connectedStreams.Add(1)
	cleanupFns = append(cleanupFns, func() {
		connectedStreams.Add(-1)
		_ = relayConn.Close()
	})
	log.Printf("TCP relayed-address=%s", relayConn.LocalAddr().String())
	emitProxyStatus("turn_ready")

	dtlsConn, err := dtlsFunc(ctx, &relayPacketConn{relay: relayConn, peer: peer}, peer)
	if err != nil {
		cleanup()
		return nil, nil, fmt.Errorf("DTLS handshake: %w", err)
	}
	cleanupFns = append(cleanupFns, func() { _ = dtlsConn.Close() })
	emitProxyStatus("dtls_ready")

	if err = negotiateMainlineTCPTransport(dtlsConn); err != nil {
		cleanup()
		return nil, nil, err
	}

	kcpSession, err := tcputil.NewKCPOverDTLS(dtlsConn, false)
	if err != nil {
		cleanup()
		return nil, nil, fmt.Errorf("KCP session: %w", err)
	}
	cleanupFns = append(cleanupFns, func() { _ = kcpSession.Close() })
	emitProxyStatus("kcp_ready")

	smuxSession, err := smux.Client(kcpSession, tcputil.DefaultSmuxConfig())
	if err != nil {
		cleanup()
		return nil, nil, fmt.Errorf("smux client: %w", err)
	}
	cleanupFns = append(cleanupFns, func() { _ = smuxSession.Close() })
	emitProxyStatus("smux_ready")

	return smuxSession, cleanup, nil
}

func negotiateMainlineTCPTransport(dtlsConn net.Conn) error {
	hello, err := sessionmuv1.BuildProbeHelloWithTransport(
		sessionproto.TransportMode_TRANSPORT_MODE_TCP,
		[]sessionproto.TransportMode{sessionproto.TransportMode_TRANSPORT_MODE_TCP},
	)
	if err != nil {
		return fmt.Errorf("build TCP probe hello: %w", err)
	}
	serverHello, err := exchangeServerHello(dtlsConn, hello)
	if err != nil {
		return fmt.Errorf("mainline TCP negotiation failed: %w", err)
	}
	if serverHello.GetVersion() != muProtocolV1 {
		return fmt.Errorf("mainline TCP transport requires mu/v1, got v%d", serverHello.GetVersion())
	}
	if serverHello.GetError() != "" {
		return fmt.Errorf("server rejected TCP transport: %s", serverHello.GetError())
	}
	if serverHello.GetSelectedTransport() != sessionproto.TransportMode_TRANSPORT_MODE_TCP {
		return fmt.Errorf("server selected transport %s instead of TCP", serverHello.GetSelectedTransport())
	}
	return nil
}

func pipeNetConns(ctx context.Context, first net.Conn, second net.Conn) {
	copyCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	context.AfterFunc(copyCtx, func() {
		_ = first.SetDeadline(time.Now())
		_ = second.SetDeadline(time.Now())
	})

	var waitGroup sync.WaitGroup
	waitGroup.Add(2)

	go func() {
		defer waitGroup.Done()
		_, _ = io.Copy(first, second)
	}()

	go func() {
		defer waitGroup.Done()
		_, _ = io.Copy(second, first)
	}()

	waitGroup.Wait()
	_ = first.SetDeadline(time.Time{})
	_ = second.SetDeadline(time.Time{})
}
