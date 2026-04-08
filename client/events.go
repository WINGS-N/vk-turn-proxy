package main

import (
	"encoding/json"
	"fmt"
	"log"
	"strings"
	"time"
)

const proxyEventProtocolVersion = 1

var proxyCapabilities = []string{
	"auth_ready",
	"captcha_lockout",
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
