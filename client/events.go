package main

import (
	"encoding/json"
	"fmt"
	"log"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cacggghp/vk-turn-proxy/appcontrolpb"
	"github.com/cacggghp/vk-turn-proxy/sessionproto"
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
	// Push to gRPC StreamTelemetry subscribers first (event-driven, no poll lag),
	// then still print the JSONL line for the logs.
	telemetryHub.publish(int32(connected))
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
	// The JSONL line stays on stdout for the log. Control now flows over the
	// AppControl StreamEvents gRPC channel: publish the same event typed there.
	fmt.Println("PROXY_EVENT: " + string(encoded))
	publishProxyEvent(payload)
}

// proxyEventBroadcaster fans relay control events out to every active
// StreamEvents subscriber. Sends are non-blocking: a subscriber that falls behind
// drops events rather than stalling the relay - control events are re-emitted
// (captcha / vk-auth) or superseded (status), so a rare drop is tolerable.
type proxyEventBroadcaster struct {
	mu   sync.Mutex
	subs map[chan *appcontrolpb.ProxyEvent]struct{}
}

var eventHub = &proxyEventBroadcaster{subs: make(map[chan *appcontrolpb.ProxyEvent]struct{})}

func (h *proxyEventBroadcaster) publish(ev *appcontrolpb.ProxyEvent) {
	h.mu.Lock()
	defer h.mu.Unlock()
	for ch := range h.subs {
		select {
		case ch <- ev:
		default:
		}
	}
}

var lastTrafficUsage atomic.Pointer[appcontrolpb.TrafficUsageEvent]

// publishTrafficUsage forwards a heartbeat's managed-client traffic-limit usage to
// the app over StreamEvents, de-duplicating unchanged readings so the frequent
// per-stream heartbeats do not flood the app. A heartbeat without usage
// (traffic_present false) is ignored - the session's client is anonymous or
// uncapped, or the node/panel is an older build.
func publishTrafficUsage(hb *sessionproto.Heartbeat) {
	if hb == nil || !hb.GetTrafficPresent() {
		return
	}
	ev := &appcontrolpb.TrafficUsageEvent{
		LimitBytes:     hb.GetTrafficLimitBytes(),
		UsedBytes:      hb.GetTrafficUsedBytes(),
		RemainingBytes: hb.GetTrafficRemainingBytes(),
		Disabled:       hb.GetTrafficDisabled(),
	}
	if prev := lastTrafficUsage.Load(); prev != nil &&
		prev.GetLimitBytes() == ev.GetLimitBytes() &&
		prev.GetUsedBytes() == ev.GetUsedBytes() &&
		prev.GetRemainingBytes() == ev.GetRemainingBytes() &&
		prev.GetDisabled() == ev.GetDisabled() {
		return
	}
	lastTrafficUsage.Store(ev)
	eventHub.publish(&appcontrolpb.ProxyEvent{Event: &appcontrolpb.ProxyEvent_TrafficUsage{TrafficUsage: ev}})
}

// publishPatchStatus reports the progress of one PatchConfig field over the same
// StreamEvents channel the app already listens on.
func publishPatchStatus(requestID, field, state, message string) {
	eventHub.publish(&appcontrolpb.ProxyEvent{Event: &appcontrolpb.ProxyEvent_PatchStatus{
		PatchStatus: &appcontrolpb.PatchStatusEvent{
			RequestId: requestID,
			Field:     field,
			State:     state,
			Message:   message,
		},
	}})
}

func (h *proxyEventBroadcaster) subscribe() chan *appcontrolpb.ProxyEvent {
	ch := make(chan *appcontrolpb.ProxyEvent, 64)
	h.mu.Lock()
	h.subs[ch] = struct{}{}
	h.mu.Unlock()
	return ch
}

func (h *proxyEventBroadcaster) unsubscribe(ch chan *appcontrolpb.ProxyEvent) {
	h.mu.Lock()
	delete(h.subs, ch)
	h.mu.Unlock()
	close(ch)
}

// publishProxyEvent maps a JSONL event struct to its typed ProxyEvent and pushes
// it to StreamEvents subscribers. Payloads with no control mapping (telemetry,
// vk_cookies_update) are logged as JSONL only and skipped here - telemetry has its
// own StreamTelemetry RPC and the app pulls rotated cookies via GetVKCookies.
func publishProxyEvent(payload any) {
	var ev *appcontrolpb.ProxyEvent
	switch p := payload.(type) {
	case proxyStatusEvent:
		ev = &appcontrolpb.ProxyEvent{Event: &appcontrolpb.ProxyEvent_Status{
			Status: &appcontrolpb.StatusEvent{Phase: p.Phase},
		}}
	case proxyStreamStatusEvent:
		ev = &appcontrolpb.ProxyEvent{Event: &appcontrolpb.ProxyEvent_Status{
			Status: &appcontrolpb.StatusEvent{Phase: p.Phase, StreamId: int32(p.StreamID)},
		}}
	case proxyDtlsAliveEvent:
		ev = &appcontrolpb.ProxyEvent{Event: &appcontrolpb.ProxyEvent_Status{
			Status: &appcontrolpb.StatusEvent{Phase: p.Phase, StreamId: int32(p.StreamID), ConnectedStreams: int32(p.ConnectedStreams)},
		}}
	case proxyCapsEvent:
		ev = &appcontrolpb.ProxyEvent{Event: &appcontrolpb.ProxyEvent_Caps{
			Caps: &appcontrolpb.CapsEvent{Version: int32(p.Version), Capabilities: append([]string(nil), p.Capabilities...)},
		}}
	case proxyCaptchaEvent:
		ev = &appcontrolpb.ProxyEvent{Event: &appcontrolpb.ProxyEvent_Captcha{
			Captcha: &appcontrolpb.CaptchaEvent{State: p.State, Source: p.Source, Url: p.URL, UserAgent: p.UserAgent},
		}}
	case proxyLockoutEvent:
		ev = &appcontrolpb.ProxyEvent{Event: &appcontrolpb.ProxyEvent_Lockout{
			Lockout: &appcontrolpb.LockoutEvent{Seconds: int32(p.Seconds)},
		}}
	case vkAccountAuthEvent:
		if p.Type == "vk_cookies_required" {
			ev = &appcontrolpb.ProxyEvent{Event: &appcontrolpb.ProxyEvent_VkCookiesRequired{
				VkCookiesRequired: &appcontrolpb.VKCookiesRequiredEvent{},
			}}
		} else {
			ev = &appcontrolpb.ProxyEvent{Event: &appcontrolpb.ProxyEvent_VkAccountAuth{
				VkAccountAuth: &appcontrolpb.VKAccountAuthEvent{
					Phase:  strings.TrimPrefix(p.Type, "vk_account_auth_"),
					Link:   p.Link,
					Reason: p.Reason,
				},
			}}
		}
	default:
		return
	}
	eventHub.publish(ev)
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
