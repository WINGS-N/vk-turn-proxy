package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cacggghp/vk-turn-proxy/internal/controlpath"
	"github.com/cacggghp/vk-turn-proxy/sessionproto"
	sessionmuv1 "github.com/cacggghp/vk-turn-proxy/sessionproto/mu/v1"
	"github.com/google/uuid"
)

const (
	muProtocolNone uint32 = 0
	muProtocolV1   uint32 = sessionmuv1.ProtocolVersion

	mainlineBootstrapTimeout = 30 * time.Second
	muReadyTimeout           = 30 * time.Second
	muProbeTimeout           = 15 * time.Second
	waitPollInterval         = 250 * time.Millisecond
	controlHeartbeatInterval = 60 * time.Second
)

type mainlineControlHandle struct {
	dtlsConn              net.Conn
	writeMu               *sync.Mutex
	probeResponses        <-chan []byte
	sessionResponses      <-chan []byte
	expectRawSessionHello *atomic.Bool
}

func buildProbeHelloForVersion(version uint32) ([]byte, error) {
	switch version {
	case muProtocolV1:
		return sessionmuv1.BuildProbeHello()
	default:
		return nil, fmt.Errorf("unsupported mu protocol version: %d", version)
	}
}

func buildSessionHelloForVersion(version uint32, sessionID []byte, streamID byte) ([]byte, error) {
	switch version {
	case muProtocolV1:
		return sessionmuv1.BuildSessionHello(sessionID, streamID)
	default:
		return nil, fmt.Errorf("unsupported mu protocol version: %d", version)
	}
}

func parseAndValidateServerHelloForVersion(payload []byte, version uint32) (*sessionproto.ServerHello, error) {
	hello, err := sessionproto.ParseServerHelloMessage(payload)
	if err != nil {
		return nil, err
	}
	if hello.GetVersion() != version {
		return nil, fmt.Errorf("unexpected server hello version: %d", hello.GetVersion())
	}
	return hello, nil
}

func buildControlHeartbeatPayload(meta controlpath.HeartbeatMeta) ([]byte, error) {
	return controlpath.BuildHeartbeat(meta)
}

func exchangeServerHello(dtlsConn net.Conn, hello []byte) (*sessionproto.ServerHello, error) {
	if err := dtlsConn.SetWriteDeadline(time.Now().Add(5 * time.Second)); err != nil {
		return nil, err
	}
	if _, err := dtlsConn.Write(hello); err != nil {
		return nil, err
	}
	if err := dtlsConn.SetWriteDeadline(time.Time{}); err != nil {
		return nil, err
	}

	buf := make([]byte, 512)
	if err := dtlsConn.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		return nil, err
	}
	n, err := dtlsConn.Read(buf)
	if err != nil {
		return nil, err
	}
	if err := dtlsConn.SetReadDeadline(time.Time{}); err != nil {
		return nil, err
	}
	return sessionproto.ParseServerHelloMessage(buf[:n])
}

func exchangeMuSessionHello(dtlsConn net.Conn, hello []byte, version uint32) (*sessionproto.ServerHello, error) {
	packet := sessionproto.BuildControlSessionRequest(hello)

	if err := dtlsConn.SetWriteDeadline(time.Now().Add(5 * time.Second)); err != nil {
		return nil, err
	}
	if _, err := dtlsConn.Write(packet); err != nil {
		return nil, err
	}
	if err := dtlsConn.SetWriteDeadline(time.Time{}); err != nil {
		return nil, err
	}

	buf := make([]byte, 512)
	if err := dtlsConn.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		return nil, err
	}
	n, err := dtlsConn.Read(buf)
	if err != nil {
		return nil, err
	}
	if err := dtlsConn.SetReadDeadline(time.Time{}); err != nil {
		return nil, err
	}

	payload := buf[:n]
	sessionPayload, ok := sessionproto.ParseControlSessionResponse(payload)
	if !ok {
		return nil, fmt.Errorf("expected wrapped session response for mu/v%d", version)
	}
	payload = sessionPayload
	return sessionproto.ParseServerHelloMessage(payload)
}

func exchangeMuSessionHelloOnActiveMainline(
	control *mainlineControlHandle,
	hello []byte,
	version uint32,
) (*sessionproto.ServerHello, error) {
	if control == nil {
		return nil, fmt.Errorf("active mainline control handle is unavailable")
	}

	packet := sessionproto.BuildControlSessionRequest(hello)

	control.writeMu.Lock()
	defer control.writeMu.Unlock()

	if err := control.dtlsConn.SetWriteDeadline(time.Now().Add(5 * time.Second)); err != nil {
		return nil, err
	}
	if _, err := control.dtlsConn.Write(packet); err != nil {
		return nil, err
	}
	if err := control.dtlsConn.SetWriteDeadline(time.Time{}); err != nil {
		return nil, err
	}

	timer := time.NewTimer(2 * time.Second)
	defer timer.Stop()
	select {
	case payload := <-control.sessionResponses:
		return parseAndValidateServerHelloForVersion(payload, version)
	case <-timer.C:
		return nil, fmt.Errorf("timed out waiting for session response")
	}
}

func negotiateMainlineFeatures(dtlsConn net.Conn, writeMu *sync.Mutex, controlResponses <-chan []byte) (uint32, bool) {
	for _, version := range []uint32{muProtocolV1} {
		hello, err := buildProbeHelloForVersion(version)
		if err != nil {
			continue
		}
		serverHello, err := exchangeMainlineProbeHello(
			dtlsConn,
			writeMu,
			controlResponses,
			sessionproto.BuildControlProbeRequest(hello),
			version,
		)
		if err != nil {
			continue
		}
		if serverHello.GetMuSupported() {
			return version, serverHello.GetControlHeartbeatSupported()
		}
		return muProtocolNone, serverHello.GetControlHeartbeatSupported()
	}
	return muProtocolNone, false
}

func startControlHeartbeatLoop(
	ctx context.Context,
	dtlsConn net.Conn,
	writeMu *sync.Mutex,
	runtime *sessionRuntime,
	streamID byte,
	meta controlpath.HeartbeatMeta,
) {
	ticker := time.NewTicker(controlHeartbeatInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if runtime != nil && !runtime.IsHeartbeatLeader(streamID) {
				continue
			}
			heartbeatMeta := meta
			if runtime != nil {
				heartbeatMeta.ActiveFlows = runtime.ActiveStreamCount()
			}
			payload, err := buildControlHeartbeatPayload(heartbeatMeta)
			if err != nil {
				log.Printf("Failed to build control heartbeat: %s", err)
				continue
			}
			packet := sessionproto.BuildControlHeartbeatRequest(payload)
			writeMu.Lock()
			if err = writeRawControlPacket(dtlsConn, packet); err != nil {
				writeMu.Unlock()
				log.Printf("Failed to write control heartbeat: %s", err)
				return
			}
			writeMu.Unlock()
		}
	}
}

func writeRawControlPacket(conn net.Conn, payload []byte) error {
	if err := conn.SetWriteDeadline(time.Now().Add(5 * time.Second)); err != nil {
		return err
	}
	if _, err := conn.Write(payload); err != nil {
		return err
	}
	return conn.SetWriteDeadline(time.Time{})
}

func exchangeMainlineProbeHello(
	dtlsConn net.Conn,
	writeMu *sync.Mutex,
	controlResponses <-chan []byte,
	packet []byte,
	version uint32,
) (*sessionproto.ServerHello, error) {
	writeMu.Lock()
	defer writeMu.Unlock()

	if err := dtlsConn.SetWriteDeadline(time.Now().Add(5 * time.Second)); err != nil {
		return nil, err
	}
	if _, err := dtlsConn.Write(packet); err != nil {
		return nil, err
	}
	if err := dtlsConn.SetWriteDeadline(time.Time{}); err != nil {
		return nil, err
	}

	timer := time.NewTimer(2 * time.Second)
	defer timer.Stop()
	select {
	case payload := <-controlResponses:
		return parseAndValidateServerHelloForVersion(payload, version)
	case <-timer.C:
		return nil, fmt.Errorf("timed out waiting for probe response")
	}
}

func resolveSessionID(sessionMode sessionproto.Mode, sessionIDFlag string) []byte {
	if sessionMode != sessionproto.ModeMu {
		return nil
	}
	if sessionIDFlag != "" {
		sessionID, err := sessionproto.ParseSessionIDHex(sessionIDFlag)
		if err != nil {
			log.Panicf("Invalid session ID: %v", err)
		}
		return sessionID
	}

	sessionID, err := uuid.New().MarshalBinary()
	if err != nil {
		log.Panicf("Failed to generate session ID: %v", err)
	}
	return sessionID
}

func waitForReady(ctx context.Context, okchan <-chan struct{}, timeout time.Duration) bool {
	if okchan == nil {
		return false
	}
	deadline := time.Now().Add(timeout)
	ticker := time.NewTicker(waitPollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-okchan:
			return true
		case <-ctx.Done():
			return false
		case <-ticker.C:
			if isCaptchaPending() {
				deadline = time.Now().Add(timeout)
				continue
			}
			if time.Now().After(deadline) {
				return false
			}
		}
	}
}

func waitForProbeVersion(ctx context.Context, probeResult <-chan uint32, timeout time.Duration) uint32 {
	if probeResult == nil {
		return muProtocolNone
	}
	deadline := time.Now().Add(timeout)
	ticker := time.NewTicker(waitPollInterval)
	defer ticker.Stop()

	for {
		select {
		case version := <-probeResult:
			return version
		case <-ctx.Done():
			return muProtocolNone
		case <-ticker.C:
			if isCaptchaPending() {
				deadline = time.Now().Add(timeout)
				continue
			}
			if time.Now().After(deadline) {
				return muProtocolNone
			}
		}
	}
}

func waitForMainlineControlHandle(
	ctx context.Context,
	controlHandle <-chan *mainlineControlHandle,
	timeout time.Duration,
) *mainlineControlHandle {
	if controlHandle == nil {
		return nil
	}
	deadline := time.Now().Add(timeout)
	ticker := time.NewTicker(waitPollInterval)
	defer ticker.Stop()

	for {
		select {
		case handle := <-controlHandle:
			return handle
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			if isCaptchaPending() {
				deadline = time.Now().Add(timeout)
				continue
			}
			if time.Now().After(deadline) {
				return nil
			}
		}
	}
}
