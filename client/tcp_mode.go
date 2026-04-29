package main

import (
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"strings"
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

var (
	skipMainlineTCPNegotiation atomic.Bool
	tcpFlavorOverride          atomic.Value // string: "auto"|"direct"|"legacy"
)

func setTcpFlavorOverride(value string) {
	value = strings.ToLower(strings.TrimSpace(value))
	if value != "direct" && value != "legacy" {
		value = "auto"
	}
	tcpFlavorOverride.Store(value)
}

func currentTcpFlavorOverride() string {
	v, _ := tcpFlavorOverride.Load().(string)
	if v == "" {
		return "auto"
	}
	return v
}

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

		smuxSession, cleanup, err := createTCPSmuxSession(ctx, turnConfig, peer, sessionID)
		if err != nil {
			if turnConfig.credsManager != nil {
				turnConfig.credsManager.ReportWorkerError(sessionID, err)
			}
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

func createTCPSmuxSession(ctx context.Context, turnConfig *turnParams, peer *net.UDPAddr, workerID int) (*smux.Session, func(), error) {
	cleanupFns := make([]func(), 0, 8)
	cleanupOnce := &sync.Once{}
	cleanup := func() {
		cleanupOnce.Do(func() {
			for idx := len(cleanupFns) - 1; idx >= 0; idx-- {
				cleanupFns[idx]()
			}
		})
	}

	user, pass, rawURL, err := turnConfig.getCreds(workerID)
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

	flavor := sessionproto.TcpTransportFlavor_TCP_TRANSPORT_FLAVOR_LEGACY_KCP_SMUX
	if !skipMainlineTCPNegotiation.Load() {
		negotiated, err := negotiateMainlineTCPTransport(dtlsConn)
		if err != nil {
			if !looksLikePlainTCPServerError(err) {
				cleanup()
				return nil, nil, err
			}
			log.Printf(
				"Mainline TCP negotiation unsupported (plain TURN server detected), reusing the same DTLS session for KCP+smux: %s",
				err,
			)
			skipMainlineTCPNegotiation.Store(true)
		} else {
			flavor = negotiated
		}
	}

	switch flavor {
	case sessionproto.TcpTransportFlavor_TCP_TRANSPORT_FLAVOR_DIRECT_SMUX:
		smuxSession, err := smux.Client(dtlsConn, tcputil.DefaultSmuxConfig())
		if err != nil {
			cleanup()
			return nil, nil, fmt.Errorf("direct smux client: %w", err)
		}
		cleanupFns = append(cleanupFns, func() { _ = smuxSession.Close() })
		emitProxyStatus("smux_ready")
		log.Printf("TCP session ready (transport flavor: direct-smux)")
		return smuxSession, cleanup, nil
	default:
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
		log.Printf("TCP session ready (transport flavor: legacy KCP+smux)")
		return smuxSession, cleanup, nil
	}
}

func looksLikePlainTCPServerError(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "timeout") ||
		strings.Contains(msg, "deadline exceeded") ||
		strings.Contains(msg, "cannot parse") ||
		strings.Contains(msg, "invalid wire-format") ||
		strings.Contains(msg, "unexpected eof") ||
		strings.Contains(msg, "connection reset")
}

func negotiateMainlineTCPTransport(dtlsConn net.Conn) (sessionproto.TcpTransportFlavor, error) {
	supportedFlavors := []sessionproto.TcpTransportFlavor{
		sessionproto.TcpTransportFlavor_TCP_TRANSPORT_FLAVOR_DIRECT_SMUX,
		sessionproto.TcpTransportFlavor_TCP_TRANSPORT_FLAVOR_LEGACY_KCP_SMUX,
	}
	preferred := preferredFlavorFromOverride(supportedFlavors)
	hello, err := sessionmuv1.BuildProbeHelloWithTcpFlavors(
		sessionproto.TransportMode_TRANSPORT_MODE_TCP,
		[]sessionproto.TransportMode{sessionproto.TransportMode_TRANSPORT_MODE_TCP},
		supportedFlavors,
		preferred,
	)
	if err != nil {
		return sessionproto.TcpTransportFlavor_TCP_TRANSPORT_FLAVOR_UNSPECIFIED, fmt.Errorf("build TCP probe hello: %w", err)
	}
	serverHello, err := exchangeServerHello(dtlsConn, hello)
	if err != nil {
		return sessionproto.TcpTransportFlavor_TCP_TRANSPORT_FLAVOR_UNSPECIFIED, fmt.Errorf("mainline TCP negotiation failed: %w", err)
	}
	if serverHello.GetVersion() != muProtocolV1 {
		return sessionproto.TcpTransportFlavor_TCP_TRANSPORT_FLAVOR_UNSPECIFIED, fmt.Errorf("mainline TCP transport requires mu/v1, got v%d", serverHello.GetVersion())
	}
	if serverHello.GetError() != "" {
		return sessionproto.TcpTransportFlavor_TCP_TRANSPORT_FLAVOR_UNSPECIFIED, fmt.Errorf("server rejected TCP transport: %s", serverHello.GetError())
	}
	if serverHello.GetSelectedTransport() != sessionproto.TransportMode_TRANSPORT_MODE_TCP {
		return sessionproto.TcpTransportFlavor_TCP_TRANSPORT_FLAVOR_UNSPECIFIED, fmt.Errorf("server selected transport %s instead of TCP", serverHello.GetSelectedTransport())
	}
	flavor := serverHello.GetSelectedTcpFlavor()
	if flavor == sessionproto.TcpTransportFlavor_TCP_TRANSPORT_FLAVOR_UNSPECIFIED {
		flavor = sessionproto.TcpTransportFlavor_TCP_TRANSPORT_FLAVOR_LEGACY_KCP_SMUX
	}
	if currentTcpFlavorOverride() == "legacy" {
		flavor = sessionproto.TcpTransportFlavor_TCP_TRANSPORT_FLAVOR_LEGACY_KCP_SMUX
	}
	return flavor, nil
}

func preferredFlavorFromOverride(supported []sessionproto.TcpTransportFlavor) sessionproto.TcpTransportFlavor {
	switch currentTcpFlavorOverride() {
	case "direct":
		return sessionproto.TcpTransportFlavor_TCP_TRANSPORT_FLAVOR_DIRECT_SMUX
	case "legacy":
		return sessionproto.TcpTransportFlavor_TCP_TRANSPORT_FLAVOR_LEGACY_KCP_SMUX
	}
	if len(supported) > 0 {
		return supported[0]
	}
	return sessionproto.TcpTransportFlavor_TCP_TRANSPORT_FLAVOR_UNSPECIFIED
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
