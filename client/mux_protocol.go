package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"sync"
	"time"

	"github.com/cacggghp/vk-turn-proxy/sessionproto"
	sessionv1 "github.com/cacggghp/vk-turn-proxy/sessionproto/v1"
	sessionv2 "github.com/cacggghp/vk-turn-proxy/sessionproto/v2"
	"github.com/google/uuid"
)

const (
	muxProtocolNone uint32 = 0
	muxProtocolV1   uint32 = sessionv1.ProtocolVersion
	muxProtocolV2   uint32 = sessionv2.ProtocolVersion

	mainlineBootstrapTimeout = 30 * time.Second
	muxReadyTimeout          = 30 * time.Second
	muxProbeTimeout          = 15 * time.Second
	waitPollInterval         = 250 * time.Millisecond
	controlHeartbeatInterval = 60 * time.Second
)

func buildProbeHelloForVersion(version uint32) ([]byte, error) {
	switch version {
	case muxProtocolV1:
		return sessionv1.BuildProbeHello()
	case muxProtocolV2:
		return sessionv2.BuildProbeHello()
	default:
		return nil, fmt.Errorf("unsupported mux protocol version: %d", version)
	}
}

func buildSessionHelloForVersion(version uint32, sessionID []byte, streamID byte) ([]byte, error) {
	switch version {
	case muxProtocolV1:
		return sessionv1.BuildSessionHello(sessionID, streamID)
	case muxProtocolV2:
		return sessionv2.BuildSessionHello(sessionID, streamID)
	default:
		return nil, fmt.Errorf("unsupported mux protocol version: %d", version)
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

func buildControlHeartbeatPayload() ([]byte, error) {
	return sessionproto.MarshalHeartbeat(&sessionproto.Heartbeat{
		Version:                       1,
		WallClockMs:                   time.Now().UnixMilli(),
		ActiveStreams:                 uint32(max(0, connectedStreams.Load())),
		Online:                        true,
		WireguardPublicKeyFingerprint: wireGuardPublicKeyFingerprint,
	})
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

func probeMuxVersionOnActiveMainline(dtlsConn net.Conn, writeMu *sync.Mutex, controlResponses <-chan []byte, version uint32, attempts int) bool {
	hello, err := buildProbeHelloForVersion(version)
	if err != nil {
		log.Printf("Failed to build v%d probe hello: %s", version, err)
		return false
	}
	controlRequest := sessionproto.BuildControlProbeRequest(hello)

	for attempt := 1; attempt <= attempts; attempt++ {
		serverHello, err := exchangeMainlineProbeHello(dtlsConn, writeMu, controlResponses, controlRequest, version)
		if err != nil {
			log.Printf("Mainline upgrade v%d probe attempt %d/%d failed: %s", version, attempt, attempts, err)
			continue
		}
		if serverHello.GetControlHeartbeatSupported() {
			return serverHello.GetMuxSupported()
		}
		if serverHello.GetMuxSupported() {
			return true
		}
		if serverHello.GetError() != "" {
			log.Printf("Mainline upgrade v%d probe rejected: %s", version, serverHello.GetError())
		}
		return false
	}

	return false
}

func negotiateMainlineFeatures(dtlsConn net.Conn, writeMu *sync.Mutex, controlResponses <-chan []byte) (uint32, bool) {
	for _, version := range []uint32{muxProtocolV2, muxProtocolV1} {
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
		if serverHello.GetMuxSupported() {
			return version, serverHello.GetControlHeartbeatSupported()
		}
		return muxProtocolNone, serverHello.GetControlHeartbeatSupported()
	}
	return muxProtocolNone, false
}

func startControlHeartbeatLoop(ctx context.Context, dtlsConn net.Conn, writeMu *sync.Mutex) {
	ticker := time.NewTicker(controlHeartbeatInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			payload, err := buildControlHeartbeatPayload()
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

func probeHighestMuxVersionOnActiveMainline(dtlsConn net.Conn, writeMu *sync.Mutex, controlResponses <-chan []byte) uint32 {
	for _, version := range []uint32{muxProtocolV2, muxProtocolV1} {
		if probeMuxVersionOnActiveMainline(dtlsConn, writeMu, controlResponses, version, 3) {
			return version
		}
	}
	return muxProtocolNone
}

func resolveSessionID(sessionMode sessionproto.Mode, sessionIDFlag string) []byte {
	if sessionMode != sessionproto.ModeMux {
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
		return muxProtocolNone
	}
	deadline := time.Now().Add(timeout)
	ticker := time.NewTicker(waitPollInterval)
	defer ticker.Stop()

	for {
		select {
		case version := <-probeResult:
			return version
		case <-ctx.Done():
			return muxProtocolNone
		case <-ticker.C:
			if isCaptchaPending() {
				deadline = time.Now().Add(timeout)
				continue
			}
			if time.Now().After(deadline) {
				return muxProtocolNone
			}
		}
	}
}
