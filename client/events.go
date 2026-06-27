package main

import (
	"encoding/json"
	"fmt"
	"log"
	"strings"
	"time"
)

const proxyEventProtocolVersion = 1
const proxyDtlsAliveStatusMinInterval = 10 * time.Second

var proxyCapabilities = []string{
	"auth_ready",
	"captcha_lockout",
	"control_failover",
	"dtls_alive",
	"manual_captcha",
	"tls_client",
	"json_events",
}

type proxyStatusEvent struct {
	Type  string `json:"type"`
	Phase string `json:"phase"`
}

// proxyStreamStatusEvent is a stream-scoped status: it attributes a phase
// (auth_ready / turn_ready / dtls_ready / ...) to the originating stream.
type proxyStreamStatusEvent struct {
	Type     string `json:"type"`
	Phase    string `json:"phase"`
	StreamID int    `json:"stream_id"`
}

type proxyLockoutEvent struct {
	Type    string `json:"type"`
	Seconds int    `json:"seconds"`
}

type proxyCaptchaEvent struct {
	Type      string `json:"type"`
	State     string `json:"state"`
	Source    string `json:"source,omitempty"`
	URL       string `json:"url,omitempty"`
	UserAgent string `json:"userAgent,omitempty"`
}

type proxyCapsEvent struct {
	Type         string   `json:"type"`
	Version      int      `json:"version"`
	Capabilities []string `json:"capabilities"`
}

type proxyTelemetryEvent struct {
	Type             string `json:"type"`
	ConnectedStreams int    `json:"connected_streams"`
}

// emitProxyStreamsTelemetry reports the current number of connected TURN
// streams so the app can show connect progress (connected/total) while
// connecting instead of jumping straight to fully connected.
func emitProxyStreamsTelemetry(connected int) {
	emitProxyEvent(proxyTelemetryEvent{
		Type:             "telemetry",
		ConnectedStreams: connected,
	})
}

func emitProxyCaps() {
	fmt.Println(
		"PROXY_CAPS: version=" +
			fmt.Sprintf("%d", proxyEventProtocolVersion) +
			" caps=" +
			strings.Join(proxyCapabilities, ","),
	)
	emitProxyEvent(proxyCapsEvent{
		Type:         "caps",
		Version:      proxyEventProtocolVersion,
		Capabilities: proxyCapabilities,
	})
}

func emitProxyEvent(payload any) {
	encoded, err := json.Marshal(payload)
	if err != nil {
		log.Printf("failed to marshal proxy event: %s", err)
		return
	}
	fmt.Println("PROXY_EVENT: " + string(encoded))
}

func applyProxyStatusState(marker string) {
	switch marker {
	case "auth_ready":
		proxyAuthReadyState.Store(true)
	case "turn_ready":
		proxyTurnReadyState.Store(true)
	case "dtls_ready", "ok":
		proxyTurnReadyState.Store(true)
		proxyDtlsReadyState.Store(true)
	}
}

func emitProxyStatus(marker string) {
	if marker == "" {
		return
	}
	applyProxyStatusState(marker)
	emitProxyEvent(proxyStatusEvent{
		Type:  "status",
		Phase: marker,
	})
}

// emitProxyStreamStatus is emitProxyStatus for a stream-scoped phase: it carries
// the originating stream id so consumers can attribute the phase to a stream.
func emitProxyStreamStatus(marker string, streamID int) {
	if marker == "" {
		return
	}
	applyProxyStatusState(marker)
	emitProxyEvent(proxyStreamStatusEvent{
		Type:     "status",
		Phase:    marker,
		StreamID: streamID,
	})
}

// proxyDtlsAliveEvent enriches the dtls_alive heartbeat with which stream
// emitted it and how many streams are currently connected, for diagnostics.
// type/phase stay identical to the plain status event for backward compatibility.
type proxyDtlsAliveEvent struct {
	Type             string `json:"type"`
	Phase            string `json:"phase"`
	StreamID         int    `json:"stream_id"`
	ConnectedStreams int    `json:"connected_streams"`
}

func emitProxyDtlsAliveStatus(streamID int) {
	now := time.Now().Unix()
	minInterval := int64(proxyDtlsAliveStatusMinInterval / time.Second)
	for {
		last := proxyDtlsAliveStatusAt.Load()
		if last > 0 && now-last < minInterval {
			return
		}
		if proxyDtlsAliveStatusAt.CompareAndSwap(last, now) {
			emitProxyEvent(proxyDtlsAliveEvent{
				Type:             "status",
				Phase:            "dtls_alive",
				StreamID:         streamID,
				ConnectedStreams: int(connectedStreams.Load()),
			})
			return
		}
	}
}

func emitCaptchaLockoutStatus(duration time.Duration) {
	seconds := int(duration.Round(time.Second) / time.Second)
	if seconds < 1 {
		seconds = 1
	}
	emitProxyStatus(fmt.Sprintf("captcha_lockout %d", seconds))
	emitProxyEvent(proxyLockoutEvent{
		Type:    "lockout",
		Seconds: seconds,
	})
}

func emitCaptchaPromptEvent(state string, source string, url string, userAgent string) {
	if state == "" {
		return
	}
	emitProxyEvent(proxyCaptchaEvent{
		Type:      "captcha",
		State:     state,
		Source:    strings.TrimSpace(source),
		URL:       strings.TrimSpace(url),
		UserAgent: strings.TrimSpace(userAgent),
	})
}

func emitCaptchaStateEvent(state string) {
	if state == "" {
		return
	}
	emitProxyEvent(proxyCaptchaEvent{
		Type:  "captcha",
		State: state,
	})
}
