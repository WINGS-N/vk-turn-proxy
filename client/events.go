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

type proxyTelemetryStreamEvent struct {
	ID               int    `json:"id"`
	Leader           bool   `json:"leader,omitempty"`
	Primary          bool   `json:"primary,omitempty"`
	TurnReady        bool   `json:"turnReady,omitempty"`
	DtlsReady        bool   `json:"dtlsReady,omitempty"`
	LastAliveMs      int64  `json:"lastAliveMs,omitempty"`
	QueueDepth       int    `json:"queueDepth,omitempty"`
	QueueCapacity    int    `json:"queueCapacity,omitempty"`
	QueueFillPercent int    `json:"queueFillPercent,omitempty"`
	OutPackets       uint64 `json:"outPackets,omitempty"`
	OutBytes         uint64 `json:"outBytes,omitempty"`
	InPackets        uint64 `json:"inPackets,omitempty"`
	InBytes          uint64 `json:"inBytes,omitempty"`
}

type proxyTelemetryEvent struct {
	Type               string                      `json:"type"`
	Reason             string                      `json:"reason,omitempty"`
	TimestampMs        int64                       `json:"timestampMs"`
	SessionMode        string                      `json:"sessionMode,omitempty"`
	ProtocolVersion    uint32                      `json:"protocolVersion,omitempty"`
	SessionID          string                      `json:"sessionId,omitempty"`
	ActiveStreams      int                         `json:"activeStreams"`
	ConnectedStreams   int                         `json:"connectedStreams"`
	LeaderStream       *int                        `json:"leaderStream,omitempty"`
	PrimaryStream      *int                        `json:"primaryStream,omitempty"`
	ControlHeartbeat   bool                        `json:"controlHeartbeat,omitempty"`
	DispatcherEnabled  bool                        `json:"dispatcherEnabled,omitempty"`
	DispatchDropped    uint64                      `json:"dispatchDropped,omitempty"`
	DispatchReassigned uint64                      `json:"dispatchReassigned,omitempty"`
	DispatchPrimary    uint64                      `json:"dispatchPrimary,omitempty"`
	DispatchSpillover  uint64                      `json:"dispatchSpillover,omitempty"`
	Streams            []proxyTelemetryStreamEvent `json:"streams,omitempty"`
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

func emitProxyStatus(marker string) {
	if marker == "" {
		return
	}
	switch marker {
	case "auth_ready":
		proxyAuthReadyState.Store(true)
	case "turn_ready":
		proxyTurnReadyState.Store(true)
	case "dtls_ready", "ok":
		proxyTurnReadyState.Store(true)
		proxyDtlsReadyState.Store(true)
	}
	fmt.Println("PROXY_STATUS: " + marker)
	emitProxyEvent(proxyStatusEvent{
		Type:  "status",
		Phase: marker,
	})
}

func emitProxyDtlsAliveStatus() {
	now := time.Now().Unix()
	minInterval := int64(proxyDtlsAliveStatusMinInterval / time.Second)
	for {
		last := proxyDtlsAliveStatusAt.Load()
		if last > 0 && now-last < minInterval {
			return
		}
		if proxyDtlsAliveStatusAt.CompareAndSwap(last, now) {
			emitProxyStatus("dtls_alive")
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

func emitProxyTelemetry(event proxyTelemetryEvent) {
	if event.Type == "" {
		return
	}
	emitProxyEvent(event)
}
