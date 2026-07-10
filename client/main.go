// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package main

import (
	"context"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net"
	"net/http"
	neturl "net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/cacggghp/vk-turn-proxy/appcontrolpb"
	"github.com/cacggghp/vk-turn-proxy/internal/controlpath"
	"github.com/cacggghp/vk-turn-proxy/internal/wrap"
	"github.com/cacggghp/vk-turn-proxy/sessionproto"
	sessionmuv1 "github.com/cacggghp/vk-turn-proxy/sessionproto/mu/v1"
	"github.com/cbeuw/connutil"
	"github.com/google/uuid"
	"github.com/pion/dtls/v3"
	"github.com/pion/dtls/v3/pkg/crypto/selfsign"
	"github.com/pion/transport/v4"
	"github.com/pion/turn/v5"
)

// clientVersion is the build version logged at startup. It is stamped at build
// time with -ldflags "-X main.clientVersion=$(git describe --tags --always --dirty)";
// the default marks an unstamped local build.
var clientVersion = "dev"

// dnsModeGlobal is set in main() from the -dns flag and consumed by the
// resolver helpers below. Default mirrors the CLI default: auto-probe UDP/53
// then sticky-fallback to DoH on total failure.
var dnsModeGlobal atomic.Pointer[string]

// dohResolverSingleton lazily constructs the process-wide DoH resolver. The
// resolver itself is goroutine-safe; bootstrap transport is reused.
var (
	dohResolverOnce sync.Once
	dohResolverInst *DohResolver
)

func setDnsMode(mode string) {
	switch mode {
	case DNSModeUDP, DNSModeDoH, DNSModeAuto:
	default:
		mode = DNSModeAuto
	}
	dnsModeGlobal.Store(&mode)
}

func dnsMode() string {
	if p := dnsModeGlobal.Load(); p != nil {
		return *p
	}
	return DNSModeAuto
}

func dnsModeIs(mode string) bool { return dnsMode() == mode }

// dohAutoLatched mirrors the autoDial sticky-flag for protectedResolver.
var dohAutoLatched atomic.Bool

func latchToDoH() { dohAutoLatched.Store(true) }

// shouldUseDoH returns true when callers should try DoH first for hostname
// resolution: explicit DoH mode, or auto mode after a UDP failure latched.
func shouldUseDoH() bool {
	switch dnsMode() {
	case DNSModeDoH:
		return true
	case DNSModeAuto:
		return dohAutoLatched.Load()
	}
	return false
}

// sharedDohResolver returns the process-wide DoH resolver, initialised on
// first call. Bridge is reused if supplied on the first call.
func sharedDohResolver(bridge *protectBridge) *DohResolver {
	dohResolverOnce.Do(func() {
		dohResolverInst = NewDohResolver(nil, bridge)
	})
	return dohResolverInst
}

type getCredsFunc func(workerID int) (string, string, string, error)

type directNet struct{}

type directDialer struct {
	*net.Dialer
}

type directListenConfig struct {
	*net.ListenConfig
}

type UDPPacket struct {
	Data []byte
	N    int
}

const (
	inboundPacketQueueSize    = 8192
	perWorkerInboundQueueSize = 128
	udpReadBufferBytes        = 4 << 20
	udpWriteBufferBytes       = 4 << 20
)

var packetPool = sync.Pool{
	New: func() any { return &UDPPacket{Data: make([]byte, 2048)} },
}

type udpBufferTunable interface {
	SetReadBuffer(bytes int) error
	SetWriteBuffer(bytes int) error
}

func tuneUDPBuffers(target any, label string) {
	conn, ok := target.(udpBufferTunable)
	if !ok || conn == nil {
		return
	}
	if err := conn.SetReadBuffer(udpReadBufferBytes); err != nil {
		log.Printf("UDP read buffer tune failed for %s: %s", label, err)
	}
	if err := conn.SetWriteBuffer(udpWriteBufferBytes); err != nil {
		log.Printf("UDP write buffer tune failed for %s: %s", label, err)
	}
}

func newDirectNet() transport.Net {
	return directNet{}
}

func (directNet) ListenPacket(network string, address string) (net.PacketConn, error) {
	conn, err := net.ListenPacket(network, address)
	if err == nil {
		pinConnToPhysical(conn)
		tuneUDPBuffers(conn, "direct listen packet")
	}
	return conn, err
}

func (directNet) ListenUDP(network string, locAddr *net.UDPAddr) (transport.UDPConn, error) {
	conn, err := net.ListenUDP(network, locAddr)
	if err == nil {
		pinConnToPhysical(conn)
		tuneUDPBuffers(conn, "direct listen udp")
	}
	return conn, err
}

func (directNet) ListenTCP(network string, laddr *net.TCPAddr) (transport.TCPListener, error) {
	listener, err := net.ListenTCP(network, laddr)
	if err != nil {
		return nil, err
	}

	return directTCPListener{listener}, nil
}

func (directNet) Dial(network, address string) (net.Conn, error) {
	conn, err := net.Dial(network, address)
	if err == nil {
		pinConnToPhysical(conn)
	}
	return conn, err
}

func (directNet) DialUDP(network string, laddr, raddr *net.UDPAddr) (transport.UDPConn, error) {
	conn, err := net.DialUDP(network, laddr, raddr)
	if err == nil {
		pinConnToPhysical(conn)
		tuneUDPBuffers(conn, "direct dial udp")
	}
	return conn, err
}

func (directNet) DialTCP(network string, laddr, raddr *net.TCPAddr) (transport.TCPConn, error) {
	conn, err := net.DialTCP(network, laddr, raddr)
	if err == nil {
		pinConnToPhysical(conn)
	}
	return conn, err
}

func (directNet) ResolveIPAddr(network, address string) (*net.IPAddr, error) {
	return net.ResolveIPAddr(network, address)
}

func (directNet) ResolveUDPAddr(network, address string) (*net.UDPAddr, error) {
	return net.ResolveUDPAddr(network, address)
}

func (directNet) ResolveTCPAddr(network, address string) (*net.TCPAddr, error) {
	return net.ResolveTCPAddr(network, address)
}

func (directNet) Interfaces() ([]*transport.Interface, error) {
	return nil, transport.ErrNotSupported
}

func (directNet) InterfaceByIndex(index int) (*transport.Interface, error) {
	return nil, fmt.Errorf("%w: index=%d", transport.ErrInterfaceNotFound, index)
}

func (directNet) InterfaceByName(name string) (*transport.Interface, error) {
	return nil, fmt.Errorf("%w: %s", transport.ErrInterfaceNotFound, name)
}

func (directNet) CreateDialer(dialer *net.Dialer) transport.Dialer {
	return directDialer{Dialer: dialer}
}

func (directNet) CreateListenConfig(listenerConfig *net.ListenConfig) transport.ListenConfig {
	return directListenConfig{ListenConfig: listenerConfig}
}

func (d directDialer) Dial(network, address string) (net.Conn, error) {
	return d.Dialer.Dial(network, address)
}

func (d directListenConfig) Listen(ctx context.Context, network, address string) (net.Listener, error) {
	return d.ListenConfig.Listen(ctx, network, address)
}

func (d directListenConfig) ListenPacket(ctx context.Context, network, address string) (net.PacketConn, error) {
	return d.ListenConfig.ListenPacket(ctx, network, address)
}

type directTCPListener struct {
	*net.TCPListener
}

func (listener directTCPListener) AcceptTCP() (transport.TCPConn, error) {
	return listener.TCPListener.AcceptTCP()
}

func parseRequestedTransport(raw string, vlessAlias bool) (sessionproto.TransportMode, error) {
	normalized := strings.TrimSpace(strings.ToLower(raw))
	if normalized == "" {
		normalized = "datagram"
	}
	if vlessAlias {
		if normalized != "datagram" && normalized != "tcp" {
			return sessionproto.TransportMode_TRANSPORT_MODE_UNSPECIFIED, fmt.Errorf("unsupported transport: %s", raw)
		}
		if normalized == "datagram" {
			normalized = "tcp"
		}
	}
	switch normalized {
	case "datagram", "udp":
		return sessionproto.TransportMode_TRANSPORT_MODE_DATAGRAM, nil
	case "tcp", "vless":
		return sessionproto.TransportMode_TRANSPORT_MODE_TCP, nil
	default:
		return sessionproto.TransportMode_TRANSPORT_MODE_UNSPECIFIED, fmt.Errorf("unsupported transport: %s", raw)
	}
}

const captchaLockoutDuration = 60 * time.Second

var (
	activeLocalPeer        atomic.Value
	localWriteOnce         sync.Once
	outboundWriteOnce      sync.Once
	manualCaptcha          bool
	captchaSolverVersion   string
	globalCaptchaLockout   atomic.Int64
	connectedStreams       atomic.Int32
	globalAppCancel        context.CancelFunc
	proxyAuthReadyState    atomic.Bool
	proxyTurnReadyState    atomic.Bool
	proxyDtlsReadyState    atomic.Bool
	proxyDtlsAliveStatusAt atomic.Int64
	handshakeSem           = make(chan struct{}, 3)
	cachedCaptchaTokenMu   sync.Mutex
	cachedCaptchaToken     string
)

func loadCachedCaptchaToken() string {
	cachedCaptchaTokenMu.Lock()
	defer cachedCaptchaTokenMu.Unlock()
	return strings.TrimSpace(cachedCaptchaToken)
}

func storeCachedCaptchaToken(token string) {
	normalized := strings.TrimSpace(token)
	if normalized == "" {
		return
	}
	cachedCaptchaTokenMu.Lock()
	cachedCaptchaToken = normalized
	cachedCaptchaTokenMu.Unlock()
}

func setCaptchaLockout(duration time.Duration) {
	globalCaptchaLockout.Store(time.Now().Add(duration).Unix())
	emitCaptchaLockoutStatus(duration)
}

func captchaLockoutRemaining() time.Duration {
	lockoutEnd := globalCaptchaLockout.Load()
	if lockoutEnd == 0 {
		return 0
	}
	remaining := time.Until(time.Unix(lockoutEnd, 0))
	if remaining < 0 {
		return 0
	}
	return remaining
}

func isCaptchaWaitRequired(err error) bool {
	return err != nil && strings.Contains(err.Error(), "CAPTCHA_WAIT_REQUIRED")
}

func isFatalCaptchaFailure(err error) bool {
	return err != nil && strings.Contains(err.Error(), "FATAL_CAPTCHA_FAILED_NO_STREAMS")
}

func wrapCaptchaFailure(err error, allowInteractiveFallback bool) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, errCaptchaDeferredAlreadyPending) {
		return err
	}
	setCaptchaLockout(captchaLockoutDuration)
	if allowInteractiveFallback && connectedStreams.Load() == 0 {
		return fmt.Errorf("FATAL_CAPTCHA_FAILED_NO_STREAMS: %w", err)
	}
	return fmt.Errorf("CAPTCHA_WAIT_REQUIRED: %w", err)
}

func vkDelayRandom(minMs, maxMs int) {
	if maxMs <= minMs {
		time.Sleep(time.Duration(minMs) * time.Millisecond)
		return
	}
	ms := minMs + rand.Intn(maxMs-minMs+1)
	time.Sleep(time.Duration(ms) * time.Millisecond)
}

type vkCred struct {
	clientID     string
	clientSecret string
}

var vkCreds = []vkCred{
	{clientID: "6287487", clientSecret: "QbYic1K3lEV5kTGiqlq2"},
	{clientID: "8202606", clientSecret: "lMRsTiMCyPnp5vfoldmn"},
}

var vkCredRotation atomic.Uint64

func nextVkCred() vkCred {
	return vkCreds[int(vkCredRotation.Add(1)-1)%len(vkCreds)]
}

func getVkCredsWithFallback(link string, resolver *protectedResolver, allowInteractiveFallback bool) (string, string, []string, time.Duration, error) {
	if remaining := captchaLockoutRemaining(); remaining > 0 {
		emitCaptchaLockoutStatus(remaining)
		return "", "", nil, 0, fmt.Errorf("CAPTCHA_WAIT_REQUIRED: global lockout active for %s", remaining.Round(time.Second))
	}

	// bypass mode: try the VK Calls captcha-free path (api.vk.me / VK Connect)
	// first. On any failure fall through to the legacy captcha-solving flow, so
	// the v2/v1 solvers still cover the case if VK gates the new path.
	if strings.EqualFold(captchaSolverVersion, "bypass") {
		user, pass, addresses, lifetime, err := getVkCredsViaVKCalls(link, resolver)
		if err == nil {
			return user, pass, addresses, lifetime, nil
		}
		log.Printf("VK Calls bypass path failed, falling back to legacy captcha flow: %v", err)
	}

	profile := getRandomProfile()
	name := generateName()
	escapedName := neturl.QueryEscape(name)
	client, err := resolver.newTLSHTTPClient(profile, 20*time.Second)
	if err != nil {
		return "", "", nil, 0, fmt.Errorf("failed to initialize tls client: %w", err)
	}
	defer client.CloseIdleConnections()

	log.Printf("Connecting identity - Name: %s | User-Agent: %s", name, profile.UserAgent)

	doRequest := func(data string, url string) (resp map[string]interface{}, err error) {
		req, err := newFHTTPRequest(context.Background(), "POST", url, []byte(data))
		if err != nil {
			return nil, err
		}

		parsedURL, _ := neturl.Parse(url)
		req.Host = parsedURL.Hostname()
		applyBrowserProfileFhttp(req, profile)
		req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("Accept", "*/*")
		req.Header.Set("Origin", "https://vk.com")
		req.Header.Set("Referer", "https://vk.com/")
		req.Header.Set("Sec-Fetch-Site", "same-site")
		req.Header.Set("Sec-Fetch-Mode", "cors")
		req.Header.Set("Sec-Fetch-Dest", "empty")
		req.Header.Set("Priority", "u=1, i")

		httpResp, err := client.Do(req)
		if err != nil {
			return nil, err
		}
		defer func() {
			if closeErr := httpResp.Body.Close(); closeErr != nil {
				log.Printf("close response body: %s", closeErr)
			}
		}()

		body, err := io.ReadAll(httpResp.Body)
		if err != nil {
			return nil, err
		}

		err = json.Unmarshal(body, &resp)
		if err != nil {
			return nil, err
		}

		return resp, nil
	}

	var resp map[string]interface{}
	defer func() {
		if r := recover(); r != nil {
			log.Panicf("get TURN creds error: %v\n\n", resp)
		}
	}()

	cred := nextVkCred()
	// The call flow uses the token_type=messages anonymous token. VK's scopes variant
	// of get_anonym_token mints an OAuth-only token that getAnonymousToken rejects with
	// anonym_token.not_found, so only the host moved to vk.com, not the params.
	data := fmt.Sprintf("client_id=%s&token_type=messages&client_secret=%s&version=1&app_id=%s", cred.clientID, cred.clientSecret, cred.clientID)
	url := "https://login.vk.com/?act=get_anonym_token"

	resp, err = doRequest(data, url)
	if err != nil {
		return "", "", nil, 0, fmt.Errorf("request error:%s", err)
	}

	dataMap, ok := resp["data"].(map[string]interface{})
	if !ok {
		return "", "", nil, 0, fmt.Errorf("unexpected anon token response: %v", resp)
	}
	token1, ok := dataMap["access_token"].(string)
	if !ok {
		return "", "", nil, 0, fmt.Errorf("missing access_token in response: %v", resp)
	}

	vkDelayRandom(100, 150)
	previewData := fmt.Sprintf("vk_join_link=https://vk.com/call/join/%s&fields=photo_200&access_token=%s", link, token1)
	_, _ = doRequest(previewData, "https://api.vk.com/method/calls.getCallPreview?v=5.282&client_id="+cred.clientID)
	vkDelayRandom(200, 400)

	data = fmt.Sprintf("vk_join_link=https://vk.com/call/join/%s&name=%s&access_token=%s", link, escapedName, token1)
	if cachedSuccessToken := loadCachedCaptchaToken(); cachedSuccessToken != "" {
		log.Printf("Reusing cached VK success_token for auth warmup")
		data += fmt.Sprintf("&success_token=%s", neturl.QueryEscape(cachedSuccessToken))
	}
	url = "https://api.vk.com/method/calls.getAnonymousToken?v=5.282&client_id=" + cred.clientID

	var token2 string
	const maxCaptchaAttempts = 3
	usedAutoCaptcha := false
	for attempt := 0; attempt <= maxCaptchaAttempts; attempt++ {
		resp, err = doRequest(data, url)
		if err != nil {
			return "", "", nil, 0, fmt.Errorf("request error:%s", err)
		}

		if errObj, hasErr := resp["error"].(map[string]interface{}); hasErr {
			errCode, _ := errObj["error_code"].(float64)
			if errCode == 14 {
				if attempt == maxCaptchaAttempts {
					return "", "", nil, 0, wrapCaptchaFailure(fmt.Errorf("captcha failed after %d attempts", maxCaptchaAttempts), allowInteractiveFallback)
				}

				captchaErr := parseVkCaptchaError(errObj)
				captchaImg, _ := errObj["captcha_img"].(string)
				log.Printf(
					"Captcha required (attempt %d/%d), sid=%s, smart=%t, interactive=%t",
					attempt+1,
					maxCaptchaAttempts,
					captchaErr.CaptchaSid,
					captchaErr.SessionToken != "",
					allowInteractiveFallback,
				)

				if captchaErr.SessionToken != "" {
					var successToken string
					var solveErr error
					if manualCaptcha {
						if allowInteractiveFallback {
							log.Printf("Manual captcha mode enabled, opening browser smart captcha flow")
							successToken, solveErr = solveCaptchaViaProxy(
								captchaErr.RedirectURI,
								resolver,
								profile.UserAgent,
							)
						} else {
							log.Printf("Manual captcha mode enabled, deferring smart captcha to app notification")
							successToken, solveErr = solveCaptchaViaProxyDeferred(
								captchaErr.RedirectURI,
								resolver,
								profile.UserAgent,
							)
						}
					} else {
						successToken, solveErr = dispatchAutoVkCaptcha(
							context.Background(),
							captchaErr,
							resolver,
							profile,
						)
						if solveErr == nil {
							usedAutoCaptcha = true
							log.Printf("VK smart captcha produced success token, retrying auth")
						} else if allowInteractiveFallback {
							log.Printf("Auto captcha solve did not complete, opening browser fallback: %s", solveErr)
							successToken, solveErr = solveCaptchaViaProxy(
								captchaErr.RedirectURI,
								resolver,
								profile.UserAgent,
							)
						} else {
							log.Printf("Auto captcha solve needs user confirmation, deferring to app notification")
							successToken, solveErr = solveCaptchaViaProxyDeferred(
								captchaErr.RedirectURI,
								resolver,
								profile.UserAgent,
							)
						}
					}
					if solveErr != nil {
						return "", "", nil, 0, wrapCaptchaFailure(fmt.Errorf("smart captcha solve error: %w", solveErr), allowInteractiveFallback)
					}
					storeCachedCaptchaToken(successToken)
					captchaAttempt := captchaErr.CaptchaAttempt
					if captchaAttempt == "" || captchaAttempt == "0" {
						captchaAttempt = "1"
					}
					data = fmt.Sprintf(
						"vk_join_link=https://vk.com/call/join/%s&name=%s&access_token=%s&captcha_key=&captcha_sid=%s&is_sound_captcha=0&success_token=%s&captcha_ts=%s&captcha_attempt=%s",
						link,
						escapedName,
						token1,
						captchaErr.CaptchaSid,
						neturl.QueryEscape(successToken),
						captchaErr.CaptchaTs,
						captchaAttempt,
					)
				} else {
					if !allowInteractiveFallback {
						if usedAutoCaptcha {
							log.Printf("VK returned image captcha after smart captcha retry, deferring to app notification")
						} else {
							log.Printf("Image captcha required, deferring to app notification")
						}
						captchaKey, solveErr := solveCaptchaViaHTTPDeferred(
							captchaImg,
							captchaErr.RedirectURI,
							resolver,
							profile.UserAgent,
						)
						if solveErr != nil {
							return "", "", nil, 0, wrapCaptchaFailure(fmt.Errorf("captcha solve error: %w", solveErr), false)
						}
						data = fmt.Sprintf(
							"vk_join_link=https://vk.com/call/join/%s&name=%s&access_token=%s&captcha_sid=%s&captcha_key=%s",
							link,
							escapedName,
							token1,
							captchaErr.CaptchaSid,
							captchaKey,
						)
						continue
					}
					if usedAutoCaptcha {
						log.Printf("VK returned image captcha after smart captcha retry, opening browser fallback")
					} else {
						log.Printf("Opening browser captcha fallback for image captcha")
					}
					captchaKey, solveErr := solveCaptchaViaHTTP(
						captchaImg,
						captchaErr.RedirectURI,
						resolver,
						profile.UserAgent,
					)
					if solveErr != nil {
						return "", "", nil, 0, wrapCaptchaFailure(fmt.Errorf("captcha solve error: %w", solveErr), true)
					}
					data = fmt.Sprintf(
						"vk_join_link=https://vk.com/call/join/%s&name=%s&access_token=%s&captcha_sid=%s&captcha_key=%s",
						link,
						escapedName,
						token1,
						captchaErr.CaptchaSid,
						captchaKey,
					)
				}
				continue
			}
			return "", "", nil, 0, fmt.Errorf("VK API error: %v", errObj)
		}

		responseMap, ok := resp["response"].(map[string]interface{})
		if !ok {
			return "", "", nil, 0, fmt.Errorf("unexpected getAnonymousToken response: %v", resp)
		}
		token2, ok = responseMap["token"].(string)
		if !ok {
			return "", "", nil, 0, fmt.Errorf("missing token in response: %v", resp)
		}
		if usedAutoCaptcha {
			log.Printf("VK smart captcha accepted by auth endpoint")
		}
		break
	}

	vkDelayRandom(100, 150)
	data = fmt.Sprintf("%s%s%s", "session_data=%7B%22version%22%3A2%2C%22device_id%22%3A%22", uuid.New(), "%22%2C%22client_version%22%3A1.1%2C%22client_type%22%3A%22SDK_JS%22%7D&method=auth.anonymLogin&format=JSON&application_key=CGMMEJLGDIHBABABA")
	url = "https://calls.okcdn.ru/fb.do"

	resp, err = doRequest(data, url)
	if err != nil {
		return "", "", nil, 0, fmt.Errorf("request error:%s", err)
	}

	token3 := resp["session_key"].(string)

	vkDelayRandom(100, 150)
	data = fmt.Sprintf("joinLink=%s&isVideo=false&protocolVersion=5&capabilities=2F7F&anonymToken=%s&method=vchat.joinConversationByLink&format=JSON&application_key=CGMMEJLGDIHBABABA&session_key=%s", link, token2, token3)
	url = "https://calls.okcdn.ru/fb.do"

	resp, err = doRequest(data, url)
	if err != nil {
		return "", "", nil, 0, fmt.Errorf("request error:%s", err)
	}

	turnServer := resp["turn_server"].(map[string]interface{})
	user := turnServer["username"].(string)
	pass := turnServer["credential"].(string)
	urlsRaw, ok := turnServer["urls"].([]interface{})
	if !ok || len(urlsRaw) == 0 {
		return "", "", nil, 0, fmt.Errorf("missing or empty urls in turn_server")
	}

	var lifetime time.Duration
	if rawLifetime, ok := turnServer["lifetime"].(float64); ok && rawLifetime > 0 {
		lifetime = time.Duration(rawLifetime) * time.Second
	} else if rawTTL, ok := turnServer["ttl"].(float64); ok && rawTTL > 0 {
		lifetime = time.Duration(rawTTL) * time.Second
	}

	var addresses []string
	for _, u := range urlsRaw {
		urlStr, ok := u.(string)
		if !ok {
			continue
		}
		clean := strings.Split(urlStr, "?")[0]
		address := strings.TrimPrefix(strings.TrimPrefix(clean, "turn:"), "turns:")
		addresses = append(addresses, address)
	}
	if len(addresses) == 0 {
		return "", "", nil, 0, fmt.Errorf("no valid TURN addresses parsed from urls")
	}
	log.Printf("VK Auth: TURN urls (%d) %v", len(addresses), addresses)

	return user, pass, addresses, lifetime, nil
}

func getYandexCreds(link string, resolver *protectedResolver) (string, string, string, error) {
	const debug = false
	const telemostConfHost = "cloud-api.yandex.ru"
	telemostConfPath := fmt.Sprintf("%s%s%s", "/telemost_front/v2/telemost/conferences/https%3A%2F%2Ftelemost.yandex.ru%2Fj%2F", link, "/connection?next_gen_media_platform_allowed=false")
	profile := getRandomProfile()
	name := generateName()

	type ConferenceResponse struct {
		URI                 string `json:"uri"`
		RoomID              string `json:"room_id"`
		PeerID              string `json:"peer_id"`
		ClientConfiguration struct {
			MediaServerURL string `json:"media_server_url"`
		} `json:"client_configuration"`
		Credentials string `json:"credentials"`
	}

	type PartMeta struct {
		Name        string `json:"name"`
		Role        string `json:"role"`
		Description string `json:"description"`
		SendAudio   bool   `json:"sendAudio"`
		SendVideo   bool   `json:"sendVideo"`
	}

	type PartAttrs struct {
		Name        string `json:"name"`
		Role        string `json:"role"`
		Description string `json:"description"`
	}

	type SdkInfo struct {
		Implementation string `json:"implementation"`
		Version        string `json:"version"`
		UserAgent      string `json:"userAgent"`
		HwConcurrency  int    `json:"hwConcurrency"`
	}

	type Capabilities struct {
		OfferAnswerMode             []string `json:"offerAnswerMode"`
		InitialSubscriberOffer      []string `json:"initialSubscriberOffer"`
		SlotsMode                   []string `json:"slotsMode"`
		SimulcastMode               []string `json:"simulcastMode"`
		SelfVadStatus               []string `json:"selfVadStatus"`
		DataChannelSharing          []string `json:"dataChannelSharing"`
		VideoEncoderConfig          []string `json:"videoEncoderConfig"`
		DataChannelVideoCodec       []string `json:"dataChannelVideoCodec"`
		BandwidthLimitationReason   []string `json:"bandwidthLimitationReason"`
		SdkDefaultDeviceManagement  []string `json:"sdkDefaultDeviceManagement"`
		JoinOrderLayout             []string `json:"joinOrderLayout"`
		PinLayout                   []string `json:"pinLayout"`
		SendSelfViewVideoSlot       []string `json:"sendSelfViewVideoSlot"`
		ServerLayoutTransition      []string `json:"serverLayoutTransition"`
		SdkPublisherOptimizeBitrate []string `json:"sdkPublisherOptimizeBitrate"`
		SdkNetworkLostDetection     []string `json:"sdkNetworkLostDetection"`
		SdkNetworkPathMonitor       []string `json:"sdkNetworkPathMonitor"`
		PublisherVp9                []string `json:"publisherVp9"`
		SvcMode                     []string `json:"svcMode"`
		SubscriberOfferAsyncAck     []string `json:"subscriberOfferAsyncAck"`
		SvcModes                    []string `json:"svcModes"`
		ReportTelemetryModes        []string `json:"reportTelemetryModes"`
		KeepDefaultDevicesModes     []string `json:"keepDefaultDevicesModes"`
	}

	type HelloPayload struct {
		ParticipantMeta        PartMeta     `json:"participantMeta"`
		ParticipantAttributes  PartAttrs    `json:"participantAttributes"`
		SendAudio              bool         `json:"sendAudio"`
		SendVideo              bool         `json:"sendVideo"`
		SendSharing            bool         `json:"sendSharing"`
		ParticipantID          string       `json:"participantId"`
		RoomID                 string       `json:"roomId"`
		ServiceName            string       `json:"serviceName"`
		Credentials            string       `json:"credentials"`
		CapabilitiesOffer      Capabilities `json:"capabilitiesOffer"`
		SdkInfo                SdkInfo      `json:"sdkInfo"`
		SdkInitializationID    string       `json:"sdkInitializationId"`
		DisablePublisher       bool         `json:"disablePublisher"`
		DisableSubscriber      bool         `json:"disableSubscriber"`
		DisableSubscriberAudio bool         `json:"disableSubscriberAudio"`
	}

	type HelloRequest struct {
		UID   string       `json:"uid"`
		Hello HelloPayload `json:"hello"`
	}

	type FlexUrls []string

	type WSSResponse struct {
		UID         string `json:"uid"`
		ServerHello struct {
			RtcConfiguration struct {
				IceServers []struct {
					Urls       FlexUrls `json:"urls"`
					Username   string   `json:"username,omitempty"`
					Credential string   `json:"credential,omitempty"`
				} `json:"iceServers"`
			} `json:"rtcConfiguration"`
		} `json:"serverHello"`
	}

	type WSSAck struct {
		UID string `json:"uid"`
		Ack struct {
			Status struct {
				Code string `json:"code"`
			} `json:"status"`
		} `json:"ack"`
	}

	type WSSData struct {
		ParticipantID string
		RoomID        string
		Credentials   string
		Wss           string
	}

	endpoint := "https://" + telemostConfHost + telemostConfPath
	client := resolver.newHTTPClient(20 * time.Second)
	defer client.CloseIdleConnections()
	req, err := http.NewRequest("GET", endpoint, nil)
	if err != nil {
		return "", "", "", err
	}
	applyBrowserProfile(req, profile)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Referer", "https://telemost.yandex.ru/")
	req.Header.Set("Origin", "https://telemost.yandex.ru")
	req.Header.Set("Client-Instance-Id", uuid.New().String())

	resp, err := client.Do(req)
	if err != nil {
		return "", "", "", err
	}
	defer func() {
		if closeErr := resp.Body.Close(); closeErr != nil {
			log.Printf("close response body: %s", closeErr)
		}
	}()
	if resp.StatusCode != http.StatusOK {
		readBody, err2 := io.ReadAll(resp.Body)
		if err2 != nil {
			return "", "", "", fmt.Errorf("GetConference: status=%s (failed to read body: %v)", resp.Status, err2)
		}
		return "", "", "", fmt.Errorf("GetConference: status=%s body=%s", resp.Status, string(readBody))
	}

	var result ConferenceResponse
	if err = json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", "", "", fmt.Errorf("decode conf: %v", err)
	}
	data := WSSData{
		ParticipantID: result.PeerID,
		RoomID:        result.RoomID,
		Credentials:   result.Credentials,
		Wss:           result.ClientConfiguration.MediaServerURL,
	}
	h := http.Header{}
	h.Set("Origin", "https://telemost.yandex.ru")
	applyBrowserProfile(&http.Request{Header: h}, profile)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	dialer := resolver.newWebsocketDialer(15 * time.Second)
	conn, wsResp, err := dialer.DialContext(ctx, data.Wss, h)
	if wsResp != nil && wsResp.Body != nil {
		_ = wsResp.Body.Close()
	}
	if err != nil {
		return "", "", "", fmt.Errorf("ws dial: %w", err)
	}
	defer func() {
		if closeErr := conn.Close(); closeErr != nil {
			log.Printf("close websocket: %s", closeErr)
		}
	}()

	req1 := HelloRequest{
		UID: uuid.New().String(),
		Hello: HelloPayload{
			ParticipantMeta: PartMeta{
				Name:        name,
				Role:        "SPEAKER",
				Description: "",
				SendAudio:   false,
				SendVideo:   false,
			},
			ParticipantAttributes: PartAttrs{
				Name:        name,
				Role:        "SPEAKER",
				Description: "",
			},
			SendAudio:   false,
			SendVideo:   false,
			SendSharing: false,

			ParticipantID: data.ParticipantID,
			RoomID:        data.RoomID,
			ServiceName:   "telemost",
			Credentials:   data.Credentials,
			SdkInfo: SdkInfo{
				Implementation: "browser",
				Version:        "5.15.0",
				UserAgent:      profile.UserAgent,
				HwConcurrency:  4,
			},
			SdkInitializationID:    uuid.New().String(),
			DisablePublisher:       false,
			DisableSubscriber:      false,
			DisableSubscriberAudio: false,
			CapabilitiesOffer: Capabilities{
				OfferAnswerMode:             []string{"SEPARATE"},
				InitialSubscriberOffer:      []string{"ON_HELLO"},
				SlotsMode:                   []string{"FROM_CONTROLLER"},
				SimulcastMode:               []string{"DISABLED"},
				SelfVadStatus:               []string{"FROM_SERVER"},
				DataChannelSharing:          []string{"TO_RTP"},
				VideoEncoderConfig:          []string{"NO_CONFIG"},
				DataChannelVideoCodec:       []string{"VP8"},
				BandwidthLimitationReason:   []string{"BANDWIDTH_REASON_DISABLED"},
				SdkDefaultDeviceManagement:  []string{"SDK_DEFAULT_DEVICE_MANAGEMENT_DISABLED"},
				JoinOrderLayout:             []string{"JOIN_ORDER_LAYOUT_DISABLED"},
				PinLayout:                   []string{"PIN_LAYOUT_DISABLED"},
				SendSelfViewVideoSlot:       []string{"SEND_SELF_VIEW_VIDEO_SLOT_DISABLED"},
				ServerLayoutTransition:      []string{"SERVER_LAYOUT_TRANSITION_DISABLED"},
				SdkPublisherOptimizeBitrate: []string{"SDK_PUBLISHER_OPTIMIZE_BITRATE_DISABLED"},
				SdkNetworkLostDetection:     []string{"SDK_NETWORK_LOST_DETECTION_DISABLED"},
				SdkNetworkPathMonitor:       []string{"SDK_NETWORK_PATH_MONITOR_DISABLED"},
				PublisherVp9:                []string{"PUBLISH_VP9_DISABLED"},
				SvcMode:                     []string{"SVC_MODE_DISABLED"},
				SubscriberOfferAsyncAck:     []string{"SUBSCRIBER_OFFER_ASYNC_ACK_DISABLED"},
				SvcModes:                    []string{"FALSE"},
				ReportTelemetryModes:        []string{"TRUE"},
				KeepDefaultDevicesModes:     []string{"TRUE"},
			},
		},
	}

	if debug {
		b, _ := json.MarshalIndent(req1, "", "  ")
		log.Printf("Sending HELLO:\n%s", string(b))
	}

	if err := conn.WriteJSON(req1); err != nil {
		return "", "", "", fmt.Errorf("ws write: %w", err)
	}

	if err := conn.SetReadDeadline(time.Now().Add(15 * time.Second)); err != nil {
		return "", "", "", fmt.Errorf("ws set read deadline: %w", err)
	}

	for {
		_, msg, err := conn.ReadMessage()
		if err != nil {
			return "", "", "", fmt.Errorf("ws read: %w", err)
		}
		if debug {
			s := string(msg)
			if len(s) > 800 {
				s = s[:800] + "...(truncated)"
			}
			log.Printf("WSS recv: %s", s)
		}

		var ack WSSAck
		if err := json.Unmarshal(msg, &ack); err == nil && ack.Ack.Status.Code != "" {
			continue
		}

		var resp WSSResponse
		if err := json.Unmarshal(msg, &resp); err == nil {
			ice := resp.ServerHello.RtcConfiguration.IceServers
			for _, s := range ice {
				for _, u := range s.Urls {
					if !strings.HasPrefix(u, "turn:") && !strings.HasPrefix(u, "turns:") {
						continue
					}
					if strings.Contains(u, "transport=tcp") {
						continue
					}
					clean := strings.Split(u, "?")[0]
					address := strings.TrimPrefix(strings.TrimPrefix(clean, "turn:"), "turns:")

					return s.Username, s.Credential, address, nil
				}
			}
		}
	}
}

func dtlsFunc(ctx context.Context, conn net.PacketConn, peer *net.UDPAddr) (net.Conn, error) {
	certificate, err := selfsign.GenerateSelfSigned()
	if err != nil {
		return nil, err
	}

	select {
	case handshakeSem <- struct{}{}:
		defer func() { <-handshakeSem }()
	case <-ctx.Done():
		return nil, ctx.Err()
	}

	ctx1, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	dtlsConn, err := dtls.ClientWithOptions(conn, peer,
		dtls.WithCertificates([]tls.Certificate{certificate}...),
		dtls.WithInsecureSkipVerify(true),
		dtls.WithExtendedMasterSecret(dtls.RequireExtendedMasterSecret),
		dtls.WithCipherSuites(dtls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256),
		dtls.WithConnectionIDGenerator(dtls.OnlySendCIDGenerator()),
	)
	if err != nil {
		return nil, err
	}

	if err := dtlsConn.HandshakeContext(ctx1); err != nil {
		return nil, err
	}
	return dtlsConn, nil
}

const workerReconnectBackoff = 1500 * time.Millisecond

func waitReconnectBackoff(ctx context.Context) bool {
	timer := time.NewTimer(workerReconnectBackoff)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}

func shouldSuppressWorkerError(ctx context.Context, err error) bool {
	if err == nil {
		return false
	}
	if ctx.Err() != nil {
		return true
	}
	if errors.Is(err, net.ErrClosed) {
		return true
	}
	return false
}

func startDtlsTurnWorkers(
	ctx context.Context,
	peer *net.UDPAddr,
	listenConn net.PacketConn,
	inboundChan <-chan *UDPPacket,
	params *turnParams,
	t <-chan time.Time,
	n int,
	sessionMode sessionproto.Mode,
	sessionID []byte,
	protocolVersion uint32,
	firstReady chan struct{},
	firstProbeResult chan<- uint32,
	firstMainlineControl chan<- *mainlineControlHandle,
	runtime *sessionRuntime,
	probeOnly bool,
	statusEnabled bool,
) *sync.WaitGroup {
	wg := &sync.WaitGroup{}
	delayAdditionalWorkers := sessionMode == sessionproto.ModeMainline && !probeOnly && firstReady != nil
	if runtime != nil && runtime.DispatchesInbound() {
		wg.Go(func() {
			runtime.RunInboundDispatchLoop(ctx, inboundChan)
		})
	}

	startDtlsTurnWorker(
		wg,
		ctx,
		peer,
		listenConn,
		inboundChan,
		params,
		t,
		sessionMode,
		sessionID,
		protocolVersion,
		0,
		firstReady,
		firstProbeResult,
		firstMainlineControl,
		runtime,
		probeOnly,
		statusEnabled,
	)

	spawnAdditionalWorkers := func() {
		startAdditionalDtlsTurnWorkers(
			wg,
			ctx,
			peer,
			listenConn,
			inboundChan,
			params,
			t,
			max(0, n-1),
			1,
			sessionMode,
			sessionID,
			protocolVersion,
			runtime,
			probeOnly,
			statusEnabled,
		)
	}

	// Stash a single-worker spawner for the active (non-probe) session so a
	// thread-count PatchConfig can ramp the fleet up at runtime. A worker spawned
	// this way reads the current live snapshot on connect (endpoint/WRAP/etc.).
	if !probeOnly && statusEnabled {
		workers.setSpawn(func(streamID byte) {
			startDtlsTurnWorker(
				wg,
				ctx,
				peer,
				listenConn,
				inboundChan,
				params,
				t,
				sessionMode,
				sessionID,
				protocolVersion,
				streamID,
				nil,
				nil,
				nil,
				runtime,
				probeOnly,
				statusEnabled,
			)
		})
	}

	if !delayAdditionalWorkers {
		spawnAdditionalWorkers()
		return wg
	}

	wg.Go(func() {
		select {
		case <-ctx.Done():
			return
		case <-firstReady:
		}
		spawnAdditionalWorkers()
	})

	return wg
}

func startAdditionalDtlsTurnWorkers(
	wg *sync.WaitGroup,
	ctx context.Context,
	peer *net.UDPAddr,
	listenConn net.PacketConn,
	inboundChan <-chan *UDPPacket,
	params *turnParams,
	t <-chan time.Time,
	count int,
	firstStreamID byte,
	sessionMode sessionproto.Mode,
	sessionID []byte,
	protocolVersion uint32,
	runtime *sessionRuntime,
	probeOnly bool,
	statusEnabled bool,
) {
	for i := 0; i < count; i++ {
		streamID := byte(int(firstStreamID) + i)
		startDtlsTurnWorker(
			wg,
			ctx,
			peer,
			listenConn,
			inboundChan,
			params,
			t,
			sessionMode,
			sessionID,
			protocolVersion,
			streamID,
			nil,
			nil,
			nil,
			runtime,
			probeOnly,
			statusEnabled,
		)
	}
}

func startDtlsTurnWorker(
	wg *sync.WaitGroup,
	ctx context.Context,
	peer *net.UDPAddr,
	listenConn net.PacketConn,
	inboundChan <-chan *UDPPacket,
	params *turnParams,
	t <-chan time.Time,
	sessionMode sessionproto.Mode,
	sessionID []byte,
	protocolVersion uint32,
	streamID byte,
	firstReady chan struct{},
	firstProbeResult chan<- uint32,
	firstMainlineControl chan<- *mainlineControlHandle,
	runtime *sessionRuntime,
	probeOnly bool,
	statusEnabled bool,
) {
	connchan := make(chan net.PacketConn)
	// Real (non-probe) workers get their own cancelable context registered with the
	// supervisor, so a thread-count patch can drain individual streams. Probe workers
	// are transient and stay on the parent context.
	workerCtx := ctx
	if !probeOnly {
		var workerCancel context.CancelFunc
		workerCtx, workerCancel = context.WithCancel(ctx)
		workers.register(int(streamID), workerCancel)
	}
	wg.Go(func() {
		oneDtlsConnectionLoop(
			workerCtx,
			params,
			peer,
			listenConn,
			inboundChan,
			connchan,
			firstReady,
			firstProbeResult,
			firstMainlineControl,
			sessionMode,
			sessionID,
			protocolVersion,
			streamID,
			runtime,
			probeOnly,
			statusEnabled,
		)
	})
	wg.Go(func() {
		oneTurnConnectionLoop(workerCtx, params, peer, connchan, t, int(streamID), runtime, probeOnly, statusEnabled)
	})
}

func oneDtlsConnection(
	ctx context.Context,
	turnParams *turnParams,
	peer *net.UDPAddr,
	listenConn net.PacketConn,
	inboundChan <-chan *UDPPacket,
	connchan chan<- net.PacketConn,
	okchan chan<- struct{},
	probeResult chan<- uint32,
	mainlineControl chan<- *mainlineControlHandle,
	c chan<- error,
	sessionMode sessionproto.Mode,
	sessionID []byte,
	protocolVersion uint32,
	streamID byte,
	runtime *sessionRuntime,
	probeOnly bool,
	statusEnabled bool,
) {
	time.Sleep(time.Duration(rand.Intn(400)+100) * time.Millisecond)
	// Adopt the current live snapshot for this DTLS connection: peer (endpoint) and
	// WRAP negotiation both come from it, so a stream that migrated to a new
	// endpoint negotiates that endpoint's WRAP in the same reconnect.
	dtlsSnap := currentLive()
	var err error
	defer func() { c <- err }()
	if runtime != nil {
		runtime.EnsureStream(streamID)
		defer runtime.RemoveStream(streamID)
	}
	dtlsctx, dtlscancel := context.WithCancel(ctx)
	defer dtlscancel()
	workerInboundChan := inboundChan
	if runtime != nil && runtime.DispatchesInbound() {
		ownChan := make(chan *UDPPacket, perWorkerInboundQueueSize)
		runtime.BindDispatchChannel(streamID, ownChan)
		defer runtime.UnbindDispatchChannel(streamID)
		workerInboundChan = ownChan
	}
	var conn1, conn2 net.PacketConn
	conn1, conn2 = connutil.AsyncPacketPipe()
	defer func() {
		_ = conn2.Close()
		_ = conn1.Close()
	}()
	go func() {
		for {
			select {
			case <-dtlsctx.Done():
				return
			case connchan <- conn2:
			}
		}
	}()
	dtlsConn, err1 := dtlsFunc(dtlsctx, conn1, dtlsSnap.peer)
	if err1 != nil {
		err = fmt.Errorf("failed to connect DTLS: %s", err1)
		return
	}
	defer func() {
		if closeErr := dtlsConn.Close(); closeErr != nil {
			if ctx.Err() == nil {
				err = fmt.Errorf("failed to close DTLS connection: %s", closeErr)
			}
			return
		}
		log.Printf("Closed DTLS connection\n")
	}()
	if !probeOnly {
		// If an enrollment is parked, run the PROVISION exchange as the first hello
		// on this connection, then fall through to the normal session hello on the
		// SAME connection - the node treats PROVISION as a non-terminal prefix hello
		// (like PROBE) and keeps the connection for the session that follows, so
		// this worker's stream is reused rather than reconnected.
		runPendingProvisionOnConn(dtlsConn)
	}
	dtlsWriteMu := &sync.Mutex{}
	controlResponses := make(chan []byte, 4)
	sessionResponses := make(chan []byte, 4)
	var expectRawSessionHello atomic.Bool
	controlHeartbeatSupported := false
	if sessionMode == sessionproto.ModeMu {
		// Propose our WRAP ciphers (in preference order) and optionally
		// our key. The server picks one in ServerHello; we Enable wrap
		// on this worker's per-conn StatefulConn afterwards.
		supportedWrap := clientSupportedWrapCiphers(dtlsSnap.wrapCipher)
		var keyProposal []byte
		if dtlsSnap.wrapSendKey && len(dtlsSnap.wrapKey) == wrap.KeyLen {
			keyProposal = dtlsSnap.wrapKey
		}
		hello, err1 := buildSessionHelloForVersionWithWrap(
			protocolVersion, sessionID, streamID, supportedWrap, keyProposal,
		)
		if err1 != nil {
			err = fmt.Errorf("failed to build session hello: %s", err1)
			return
		}
		serverHello, err1 := exchangeMuSessionHello(dtlsConn, hello, protocolVersion)
		if err1 != nil {
			err = fmt.Errorf("failed to complete mu negotiation: %s", err1)
			return
		}
		if !serverHello.GetMuSupported() {
			if serverHello.GetError() != "" {
				err = fmt.Errorf("server rejected mu negotiation: %s", serverHello.GetError())
			} else {
				err = fmt.Errorf("server rejected mu negotiation")
			}
			return
		}
		controlHeartbeatSupported = serverHello.GetControlHeartbeatSupported()
		if enableErr := applyServerWrapChoice(turnParams, dtlsSnap, int(streamID), serverHello); enableErr != nil {
			// A WRAP negotiation failure on this snapshot may mean a live WRAP change
			// is unsafe (e.g. in-band turned off with no server preset); flag it so a
			// migration watching this generation can roll WRAP back.
			recordWrapFailure(dtlsSnap.gen)
			err = enableErr
			return
		}
		log.Printf("Established DTLS connection and completed mu negotiation for stream %d!\n", streamID)
	} else {
		if probeOnly {
			log.Printf("Established DTLS probe connection!\n")
		} else {
			log.Printf("Established DTLS connection!\n")
		}
	}
	if runtime != nil {
		runtime.SetProtocolVersion(protocolVersion)
		if controlHeartbeatSupported {
			runtime.SetControlHeartbeatSupported(true)
		}
		runtime.NoteDtlsReady(streamID)
	}
	if sessionMode != sessionproto.ModeMu && streamID == 0 && mainlineControl != nil {
		select {
		case mainlineControl <- &mainlineControlHandle{
			dtlsConn:              dtlsConn,
			writeMu:               dtlsWriteMu,
			probeResponses:        controlResponses,
			sessionResponses:      sessionResponses,
			expectRawSessionHello: &expectRawSessionHello,
		}:
		default:
		}
	}
	if runtime != nil {
		go startControlHeartbeatLoop(
			dtlsctx,
			dtlsConn,
			dtlsWriteMu,
			runtime,
			streamID,
			controlpath.HeartbeatMeta{
				SessionMode: string(sessionMode),
				ControlPath: controlpath.PathTurnDTLS,
				Provider:    controlpath.ProviderTurn,
				Transport:   sessionproto.TransportMode_TRANSPORT_MODE_DATAGRAM,
			},
		)
	}
	if !probeOnly && statusEnabled {
		emitProxyStreamStatus("dtls_ready", int(streamID))
	}
	if okchan != nil {
		go func() {
			select {
			case <-dtlsctx.Done():
			case okchan <- struct{}{}:
			}
		}()
	}

	wg := sync.WaitGroup{}
	wg.Add(1)
	context.AfterFunc(dtlsctx, func() {
		if err := dtlsConn.SetDeadline(time.Now()); err != nil {
			if dtlsctx.Err() == nil {
				log.Printf("Failed to set DTLS deadline: %s", err)
			}
		}
	})
	if !probeOnly {
		go func() {
			defer dtlscancel()
			for {
				select {
				case <-dtlsctx.Done():
					return
				case pkt, ok := <-workerInboundChan:
					if !ok {
						return
					}
					dtlsWriteMu.Lock()
					_, err1 := dtlsConn.Write(pkt.Data[:pkt.N])
					dtlsWriteMu.Unlock()
					if err1 == nil {
						outboundWriteOnce.Do(func() {
							log.Printf("[local] first WG write to DTLS stream %d (%d bytes)", streamID, pkt.N)
						})
					}
					if err1 == nil && runtime != nil {
						runtime.NoteOutbound(streamID, pkt.N)
					}
					packetPool.Put(pkt)
					if err1 != nil {
						if !shouldSuppressWorkerError(dtlsctx, err1) {
							log.Printf("Failed: %s", err1)
						}
						return
					}
				}
			}
		}()
	}

	// Start read-loop on dtlsConn
	go func() {
		defer wg.Done()
		defer dtlscancel()
		buf := make([]byte, 1600)
		for {
			select {
			case <-dtlsctx.Done():
				return
			default:
			}
			n, err1 := dtlsConn.Read(buf)
			if err1 != nil {
				if !shouldSuppressWorkerError(dtlsctx, err1) {
					log.Printf("Failed: %s", err1)
				}
				return
			}
			if runtime != nil {
				runtime.NoteDtlsAlive(streamID)
			}
			if payload, ok := sessionproto.ParseControlProbeResponse(buf[:n]); ok {
				select {
				case controlResponses <- append([]byte(nil), payload...):
				default:
					log.Printf("Dropped stale control response")
				}
				continue
			}
			if payload, ok := sessionproto.ParseControlHeartbeatResponse(buf[:n]); ok {
				if hb, parseErr := sessionproto.ParseHeartbeatMessage(payload); parseErr != nil {
					log.Printf("Failed to parse control heartbeat response: %s", parseErr)
				} else {
					// Surface any managed-client traffic-limit usage the node echoed.
					publishTrafficUsage(hb)
					if !probeOnly && (statusEnabled || proxyDtlsReadyState.Load()) {
						emitProxyDtlsAliveStatus(int(streamID))
					}
				}
				continue
			}
			if payload, ok := sessionproto.ParseControlSessionResponse(buf[:n]); ok {
				select {
				case sessionResponses <- append([]byte(nil), payload...):
				default:
					log.Printf("Dropped stale session response")
				}
				continue
			}
			if expectRawSessionHello.Load() {
				if _, parseErr := sessionproto.ParseServerHelloMessage(buf[:n]); parseErr == nil {
					select {
					case sessionResponses <- append([]byte(nil), buf[:n]...):
					default:
						log.Printf("Dropped stale raw session response")
					}
					continue
				}
			}
			if probeOnly {
				continue
			}
			if runtime != nil {
				runtime.NoteInbound(streamID, n)
			}
			if statusEnabled || proxyDtlsReadyState.Load() {
				emitProxyDtlsAliveStatus(int(streamID))
			}
			addr1, ok := activeLocalPeer.Load().(net.Addr)
			if !ok {
				continue
			}
			localWriteOnce.Do(func() {
				log.Printf("[local] first server->WG write to %s (%d bytes)", addr1, n)
			})

			_, err1 = listenConn.WriteTo(buf[:n], addr1)
			if err1 != nil {
				if !shouldSuppressWorkerError(dtlsctx, err1) {
					log.Printf("Failed: %s", err1)
				}
				return
			}
		}
	}()
	if sessionMode != sessionproto.ModeMu && streamID == 0 {
		go func() {
			version, heartbeatSupported := negotiateMainlineFeatures(dtlsConn, dtlsWriteMu, controlResponses)
			if runtime != nil {
				runtime.SetProtocolVersion(version)
				if heartbeatSupported {
					runtime.SetControlHeartbeatSupported(true)
				}
			}
			if probeResult != nil {
				select {
				case probeResult <- version:
				default:
				}
			}
		}()
	}

	wg.Wait()
	if err := dtlsConn.SetDeadline(time.Time{}); err != nil {
		if ctx.Err() == nil {
			log.Printf("Failed to clear DTLS deadline: %s", err)
		}
	}
}

type connectedUDPConn struct {
	*net.UDPConn
}

func (c *connectedUDPConn) WriteTo(p []byte, _ net.Addr) (int, error) {
	return c.Write(p)
}

type turnParams struct {
	host         string
	port         string
	link         string
	udp          bool
	getCreds     getCredsFunc
	resolver     *protectedResolver
	credsManager *groupedCredsManager
	// WRAP per-packet obfuscation. wrapCipher == WRAP_CIPHER_NONE /
	// _UNSPECIFIED disables WRAP regardless of wrapKey.
	wrapCipher sessionproto.WrapCipher
	wrapKey    []byte
	// wrapMode controls fallback semantics when WRAP is configured:
	//   "off"       — never wrap (wrapCipher should already be NONE)
	//   "preferred" — try WRAP, accept the server's decline; stay raw
	//                 if ServerHello.selected_wrap_cipher == NONE
	//   "required"  — fail the worker if ServerHello declines WRAP
	wrapMode string
	// wrapSendKey controls in-band key delivery: when true (default)
	// the client populates SessionHello.wrap_key_proposal with wrapKey;
	// when false the server must already have the matching key
	// configured (-wrap-key preset).
	wrapSendKey bool
	// wrapStates registers each worker's *wrap.StatefulConn under its
	// streamID so the mu/v1 SessionHello handler in oneDtlsConnection
	// can Enable wrap after the server's selected_wrap_cipher arrives.
	wrapStates *sync.Map // map[int]*wrap.StatefulConn
	// recycleGate serializes credential-rotation recycles across workers (cap 1)
	// so they roll out one stream at a time instead of all dropping at once.
	recycleGate chan struct{}
}

// liveSnapshot is the mutable, versioned view of the runtime-patchable config a
// worker adopts at (re)allocation time. PatchConfig swaps in a new snapshot and
// bumps configGeneration; the per-worker migration watcher then recycles each
// stream one at a time so the fleet drains onto the new snapshot without dropping
// traffic. A worker reads the snapshot once per allocation, so old-snapshot and
// new-snapshot streams coexist during a migration - which is exactly why WRAP and
// endpoint travel together per stream (a stream on the new endpoint also carries
// the new WRAP, see the PatchConfig handler).
type liveSnapshot struct {
	host string
	port string
	// peer is the resolved VK TURN endpoint this stream dials. WRAP and peer live
	// in the same snapshot on purpose: a stream that migrates to a new endpoint
	// also adopts that endpoint's WRAP in one coherent step, so a new-endpoint WRAP
	// is never applied to an old-endpoint stream.
	peer        *net.UDPAddr
	wrapCipher  sessionproto.WrapCipher
	wrapKey     []byte
	wrapMode    string
	wrapSendKey bool
	// gen is the config generation this snapshot represents (0 = boot). Set by
	// swapLive; workers record it in the registry so a patch can tell when the whole
	// fleet has migrated.
	gen uint64
}

var (
	liveCfg          atomic.Pointer[liveSnapshot]
	configGeneration atomic.Uint64
)

func currentLive() *liveSnapshot {
	if s := liveCfg.Load(); s != nil {
		return s
	}
	return &liveSnapshot{}
}

// swapLive installs a new snapshot (stamped with the next generation) so running
// workers migrate onto it via their migration watcher. Returns the new generation.
func swapLive(s *liveSnapshot) uint64 {
	g := configGeneration.Add(1)
	s.gen = g
	liveCfg.Store(s)
	return g
}

const (
	// credsRotationWatchInterval is how often a running TURN worker checks
	// whether its credential group rotated (TTL refresh).
	credsRotationWatchInterval = 3 * time.Second
	// recycleSettleWindow is how long a worker holds the shared rollout slot
	// after recycling, giving its replacement time to re-Allocate and finish the
	// DTLS handshake before the next worker is allowed to recycle. This keeps the
	// rollout strictly one-stream-at-a-time so the session never loses every
	// stream at once.
	recycleSettleWindow = 5 * time.Second
	// accountStreamMaxAge recycles each VK ID (account-mode) stream before its TURN
	// permission lapses. The OK server rejects pion's periodic CreatePermission
	// refresh (400), so a permission silently dies ~300s after allocation while
	// DTLS still reports alive; recycling well under that installs a fresh
	// allocation + permission. Anonymous mode refreshes fine and is left alone.
	accountStreamMaxAge = 150 * time.Second
	// accountStreamAgeJitter spreads the first recycle wave so streams do not all
	// hit max age in the same tick.
	accountStreamAgeJitter = 6 * time.Second
	// recycleConcurrencyPercent is how many streams may roll at once, as a percent
	// of the worker count (floored, min 1), so the rollout scales with the fleet.
	recycleConcurrencyPercent = 20
)

func oneTurnConnection(
	ctx context.Context,
	turnParams *turnParams,
	peer *net.UDPAddr,
	conn2 net.PacketConn,
	streamID int,
	runtime *sessionRuntime,
	c chan<- error,
	probeOnly bool,
	statusEnabled bool,
) {
	time.Sleep(time.Duration(rand.Intn(400)+100) * time.Millisecond)
	// Adopt the current live config snapshot for this allocation. A PatchConfig
	// swaps in a new snapshot and bumps configGeneration; the migration watcher
	// below recycles the stream, and the reconnect re-enters here reading the fresh
	// snapshot. So each stream carries one coherent snapshot for its lifetime.
	snap := currentLive()
	if !probeOnly {
		workers.set(streamID, snap.gen)
	}
	var err error
	// recycling marks an intentional self-recycle (creds rotation / max age):
	// turncancel() closes relayConn and the in-flight DTLS write trips a
	// "write on closed pipe", which is expected teardown, not a session failure -
	// do not surface it as a recorded error.
	var recycling atomic.Bool
	defer func() {
		if err != nil && runtime != nil && !recycling.Load() {
			runtime.NoteSessionError(byte(streamID), err)
		}
		c <- err
	}()
	defer func() {
		_ = conn2.Close()
	}()
	user, pass, url, err1 := turnParams.getCreds(streamID)
	if err1 != nil {
		err = fmt.Errorf("failed to get TURN credentials: %s", err1)
		return
	}
	if !probeOnly && statusEnabled {
		emitProxyStreamStatus("auth_ready", int(streamID))
	}
	urlhost, urlport, err1 := net.SplitHostPort(url)
	if err1 != nil {
		err = fmt.Errorf("failed to parse TURN server address: %s", err1)
		return
	}
	if snap.host != "" {
		urlhost = snap.host
	}
	if snap.port != "" {
		urlport = snap.port
	}
	var turnServerAddr string
	turnServerAddr = net.JoinHostPort(urlhost, urlport)
	turnServerUdpAddr, err1 := turnParams.resolver.ResolveUDPAddr(ctx, turnServerAddr)
	if err1 != nil {
		err = fmt.Errorf("failed to resolve TURN server address: %s", err1)
		return
	}
	turnServerAddr = turnServerUdpAddr.String()
	reportUnderlayDest(turnServerAddr) // Windows: install a /32 physical bypass route for it
	// Dial TURN Server
	var cfg *turn.ClientConfig
	var turnConn net.PacketConn
	d := turnParams.resolver.dialer()
	ctx1, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if turnParams.udp {
		rawConn, err2 := d.DialContext(ctx1, "udp", turnServerAddr)
		if err2 != nil {
			err = newTurnSetupError(turnServerAddr, fmt.Errorf("dial TURN (udp) %s: %s", turnServerAddr, err2))
			return
		}
		conn, ok := rawConn.(*net.UDPConn)
		if !ok {
			_ = rawConn.Close()
			err = fmt.Errorf("failed to cast protected UDP connection")
			return
		}
		tuneUDPBuffers(conn, "turn upstream")
		defer func() {
			if err1 = conn.Close(); err1 != nil {
				err = fmt.Errorf("failed to close TURN server connection: %s", err1)
				return
			}
		}()
		turnConn = &connectedUDPConn{conn}
	} else {
		conn, err2 := d.DialContext(ctx1, "tcp", turnServerAddr) // nolint: noctx
		if err2 != nil {
			err = newTurnSetupError(turnServerAddr, fmt.Errorf("dial TURN (tcp) %s: %s", turnServerAddr, err2))
			return
		}
		defer func() {
			if err1 = conn.Close(); err1 != nil {
				err = fmt.Errorf("failed to close TURN server connection: %s", err1)
				return
			}
		}()
		turnConn = turn.NewSTUNConn(conn)
	}
	var addrFamily turn.RequestedAddressFamily
	if peer.IP.To4() != nil {
		addrFamily = turn.RequestedAddressFamilyIPv4
	} else {
		addrFamily = turn.RequestedAddressFamilyIPv6
	}
	// Start a new TURN Client and wrap our net.Conn in a STUNConn
	// This allows us to simulate datagram based communication over a net.Conn
	cfg = &turn.ClientConfig{
		STUNServerAddr:         turnServerAddr,
		TURNServerAddr:         turnServerAddr,
		Conn:                   turnConn,
		Net:                    newDirectNet(),
		Username:               user,
		Password:               pass,
		RequestedAddressFamily: addrFamily,
		LoggerFactory:          newTurnLoggerFactory(),
	}

	client, err1 := turn.NewClient(cfg)
	if err1 != nil {
		err = fmt.Errorf("failed to create TURN client: %s", err1)
		return
	}
	defer client.Close()

	// Start listening on the conn provided.
	err1 = client.Listen()
	if err1 != nil {
		err = newTurnSetupError(turnServerAddr, fmt.Errorf("TURN listen %s: %s", turnServerAddr, err1))
		return
	}

	// Allocate a relay socket on the TURN server. On success, it
	// will return a net.PacketConn which represents the remote
	// socket.
	relayConn, err1 := client.Allocate()
	if err1 != nil {
		err = newTurnSetupError(turnServerAddr, fmt.Errorf("TURN allocate %s: %s", turnServerAddr, err1))
		return
	}
	connectedStreams.Add(1)
	emitProxyStreamsTelemetry(int(connectedStreams.Load()))
	defer func() {
		connectedStreams.Add(-1)
		emitProxyStreamsTelemetry(int(connectedStreams.Load()))
		if err1 := relayConn.Close(); err1 != nil {
			err = fmt.Errorf("failed to close TURN allocated connection: %s", err1)
		}
	}()
	if runtime != nil {
		runtime.NoteTurnReady(byte(streamID))
	}

	// The relayConn's local address is actually the transport
	// address assigned on the TURN server.
	log.Printf("[STREAM %d] relayed-address=%s", streamID, relayConn.LocalAddr().String())
	if !probeOnly && statusEnabled {
		emitProxyStreamStatus("turn_ready", int(streamID))
	}

	wg := sync.WaitGroup{}
	wg.Add(2)
	turnctx, turncancel := context.WithCancel(ctx)
	context.AfterFunc(turnctx, func() {
		if err := relayConn.SetDeadline(time.Now()); err != nil {
			if turnctx.Err() == nil {
				log.Printf("Failed to set relay deadline: %s", err)
			}
		}
		if err := conn2.SetDeadline(time.Now()); err != nil {
			if turnctx.Err() == nil {
				log.Printf("Failed to set upstream deadline: %s", err)
			}
		}
	})
	// Wrap relayConn in a *wrap.StatefulConn even when WRAP is fully
	// disabled — pass-through mode is a no-op. When mode != off the
	// cipher is installed later by the mu/v1 SessionHello handler in
	// oneDtlsConnection after the server picks a cipher via
	// ServerHello.selected_wrap_cipher.
	statefulRelay := wrap.NewStateful(relayConn)
	if turnParams.wrapStates != nil {
		turnParams.wrapStates.Store(streamID, statefulRelay)
		defer turnParams.wrapStates.Delete(streamID)
	}
	if snap.wrapMode != "" && snap.wrapMode != "off" {
		log.Printf("[STREAM %d] WRAP mode=%s; waiting for mu/v1 SessionHello to install cipher", streamID, snap.wrapMode)
	}
	// Migration watcher: when a PatchConfig bumps configGeneration, drain and
	// recycle this stream so the reconnect adopts the new live snapshot. Runs in
	// every mode (unlike the account recycler below), staggered through recycleGate
	// so the fleet migrates one stream at a time and traffic is never dropped
	// wholesale.
	if !probeOnly {
		startConfigGen := snap.gen
		go func() {
			ticker := time.NewTicker(credsRotationWatchInterval)
			defer ticker.Stop()
			for {
				select {
				case <-turnctx.Done():
					return
				case <-ticker.C:
					if configGeneration.Load() == startConfigGen {
						continue
					}
					if turnParams.recycleGate != nil {
						select {
						case turnParams.recycleGate <- struct{}{}:
						case <-turnctx.Done():
							return
						}
						time.AfterFunc(recycleSettleWindow, func() {
							<-turnParams.recycleGate
						})
					}
					log.Printf("[STREAM %d] migrating TURN allocation to new config snapshot", streamID)
					recycling.Store(true)
					turncancel()
					return
				}
			}
		}()
	}
	// Recycle this allocation when the credential group rotates its TURN
	// username/password - but only in VK ID (account) mode. There the privileged
	// token rotates frequently and pion, still holding the old username/password,
	// gets its periodic CreatePermission refresh rejected (400 Bad Request) and the
	// stream silently dies once the permission lifetime ends; turncancel() unwinds
	// both I/O loops and oneTurnConnectionLoop re-Allocates with fresh creds. The
	// per-stream stagger recycles one stream at a time so the group is not dropped
	// at once. In anonymous mode the creds are long-lived and media keeps flowing
	// over the bound channel across a rotation, so we keep the pre-recycler
	// behaviour and do not tear the stream down on rotation.
	if turnParams.credsManager != nil && getVkAuthMode() == "account" {
		startGen := turnParams.credsManager.WorkerCredGeneration(streamID)
		// Recycle before the TURN permission lapses (see accountStreamMaxAge). Jitter
		// per stream so the first wave does not all age out in the same tick.
		ageDeadline := time.Now().Add(accountStreamMaxAge + time.Duration(streamID)*accountStreamAgeJitter)
		go func() {
			ticker := time.NewTicker(credsRotationWatchInterval)
			defer ticker.Stop()
			for {
				select {
				case <-turnctx.Done():
					return
				case <-ticker.C:
					rotated := turnParams.credsManager.WorkerCredGeneration(streamID) != startGen
					aged := time.Now().After(ageDeadline)
					if !rotated && !aged {
						continue
					}
					// Roll the recycle across the group one stream at a time so the
					// session always keeps other streams live: take the shared
					// rollout slot, recycle this stream, and release the slot only
					// after a settle window long enough for the replacement to
					// re-Allocate and finish its DTLS handshake. Other workers block
					// on the slot until then, so they recycle strictly in sequence.
					if turnParams.recycleGate != nil {
						select {
						case turnParams.recycleGate <- struct{}{}:
						case <-turnctx.Done():
							return
						}
						time.AfterFunc(recycleSettleWindow, func() {
							<-turnParams.recycleGate
						})
					}
					reason := "credentials rotated"
					if aged && !rotated {
						reason = "max stream age reached"
					}
					log.Printf("[STREAM %d] recycling TURN allocation (%s) for fresh permission auth", streamID, reason)
					recycling.Store(true)
					turncancel()
					return
				}
			}
		}()
	}
	var addr atomic.Value
	// Start read-loop on conn2 (output of DTLS)
	go func() {
		defer wg.Done()
		defer turncancel()
		buf := make([]byte, 1600)
		for {
			select {
			case <-turnctx.Done():
				return
			default:
			}
			n, addr1, err1 := conn2.ReadFrom(buf)
			if err1 != nil {
				if !shouldSuppressWorkerError(turnctx, err1) {
					log.Printf("Failed: %s", err1)
				}
				return
			}

			addr.Store(addr1) // store peer

			_, err1 = statefulRelay.WriteTo(buf[:n], snap.peer)
			if err1 != nil {
				if !shouldSuppressWorkerError(turnctx, err1) {
					log.Printf("Failed: %s", err1)
				}
				return
			}
		}
	}()

	// Start read-loop on the stateful relay (auto-detects raw vs
	// SRTP-wrapped packets per byte 0, transparently unwraps wrapped
	// ones once the mu/v1 handler has installed a cipher).
	go func() {
		defer wg.Done()
		defer turncancel()
		buf := make([]byte, 1600+wrap.MaxOverhead())
		for {
			select {
			case <-turnctx.Done():
				return
			default:
			}
			n, _, err1 := statefulRelay.ReadFrom(buf)
			if err1 != nil {
				if !shouldSuppressWorkerError(turnctx, err1) {
					log.Printf("Failed: %s", err1)
				}
				return
			}
			addr1, ok := addr.Load().(net.Addr)
			if !ok {
				continue
			}
			if _, err1 = conn2.WriteTo(buf[:n], addr1); err1 != nil {
				if !shouldSuppressWorkerError(turnctx, err1) {
					log.Printf("Failed: %s", err1)
				}
				return
			}
		}
	}()

	wg.Wait()
	if err := relayConn.SetDeadline(time.Time{}); err != nil {
		if ctx.Err() == nil {
			log.Printf("Failed to clear relay deadline: %s", err)
		}
	}
	if err := conn2.SetDeadline(time.Time{}); err != nil {
		if ctx.Err() == nil {
			log.Printf("Failed to clear upstream deadline: %s", err)
		}
	}
}

func oneDtlsConnectionLoop(
	ctx context.Context,
	turnParams *turnParams,
	peer *net.UDPAddr,
	listenConn net.PacketConn,
	inboundChan <-chan *UDPPacket,
	connchan chan<- net.PacketConn,
	okchan chan<- struct{},
	probeResult chan<- uint32,
	mainlineControl chan<- *mainlineControlHandle,
	sessionMode sessionproto.Mode,
	sessionID []byte,
	protocolVersion uint32,
	streamID byte,
	runtime *sessionRuntime,
	probeOnly bool,
	statusEnabled bool,
) {
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}
		c := make(chan error)
		go oneDtlsConnection(
			ctx,
			turnParams,
			peer,
			listenConn,
			inboundChan,
			connchan,
			okchan,
			probeResult,
			mainlineControl,
			c,
			sessionMode,
			sessionID,
			protocolVersion,
			streamID,
			runtime,
			probeOnly,
			statusEnabled,
		)
		if err := <-c; err != nil {
			if ctx.Err() != nil {
				return
			}
			log.Printf("%s; reconnecting in %s", err, workerReconnectBackoff)
		} else {
			if ctx.Err() != nil {
				return
			}
			log.Printf("DTLS worker stopped; reconnecting in %s", workerReconnectBackoff)
		}
		if !waitReconnectBackoff(ctx) {
			return
		}
	}
}

func oneTurnConnectionLoop(
	ctx context.Context,
	turnParams *turnParams,
	peer *net.UDPAddr,
	connchan <-chan net.PacketConn,
	t <-chan time.Time,
	streamID int,
	runtime *sessionRuntime,
	probeOnly bool,
	statusEnabled bool,
) {
	// Deregister from the migration registry when this worker ends for good (drain
	// or shutdown), so a patch's applied-detection is not blocked by a dead stream.
	defer workers.remove(streamID)
	for {
		select {
		case <-ctx.Done():
			return
		case conn2 := <-connchan:
			select {
			case <-t:
				c := make(chan error)
				go oneTurnConnection(ctx, turnParams, peer, conn2, streamID, runtime, c, probeOnly, statusEnabled)
				if err := <-c; err != nil {
					if ctx.Err() != nil {
						return
					}
					if addr, ok := turnSetupAddr(err); ok {
						rotateStreamServer(streamID)
						markTURNServerCooldown(addr)
						log.Printf("[STREAM %d] cooling down TURN server %s after setup failure", streamID, addr)
					}
					if isFatalCaptchaFailure(err) {
						log.Printf("[STREAM %d] Fatal captcha error, shutting down runtime: %s", streamID, err)
						if globalAppCancel != nil {
							globalAppCancel()
						}
						return
					}
					if isCaptchaWaitRequired(err) {
						wait := captchaLockoutRemaining()
						if wait <= 0 {
							wait = captchaLockoutDuration
						}
						log.Printf("[STREAM %d] %s; backing off for %s", streamID, err, wait.Round(time.Second))
						timer := time.NewTimer(wait)
						select {
						case <-ctx.Done():
							timer.Stop()
							return
						case <-timer.C:
						}
						continue
					}
					log.Printf("[STREAM %d] %s; reconnecting in %s", streamID, err, workerReconnectBackoff)
				} else {
					if ctx.Err() != nil {
						return
					}
					log.Printf("[STREAM %d] TURN worker stopped; reconnecting in %s", streamID, workerReconnectBackoff)
				}
				if !waitReconnectBackoff(ctx) {
					return
				}
			default:
			}
		}
	}
}

// configureChan carries the one-shot Configure delivered by the host app over
// the AppControl gRPC. The relay boots from it instead of CLI flags.
var configureChan = make(chan *appcontrolpb.ConfigureRequest, 1)

// receiveConfigure is the AppControl ConfigureFunc: it hands the request to
// main()'s awaitConfigure. Only the first Configure is accepted.
func receiveConfigure(req *appcontrolpb.ConfigureRequest) string {
	select {
	case configureChan <- req:
		return ""
	default:
		return "configuration already delivered"
	}
}

// awaitConfigure blocks until the host app delivers a Configure, the context is
// cancelled, or the wait times out. Returns nil on cancel/timeout.
func awaitConfigure(ctx context.Context) *appcontrolpb.ConfigureRequest {
	select {
	case cfg := <-configureChan:
		return cfg
	case <-ctx.Done():
		return nil
	case <-time.After(120 * time.Second):
		return nil
	}
}

// applyConfigureToOptions folds a gRPC-delivered configuration into the parsed
// options, mirroring the former CLI flag mapping (see options.go). Empty/zero
// fields keep the parsed defaults.
func applyConfigureToOptions(opts *clientOptions, c *appcontrolpb.ConfigureRequest) {
	if c == nil {
		return
	}
	if c.GetDnsMode() != "" {
		opts.dnsMode = c.GetDnsMode()
	}
	opts.userDns = c.GetUserDns()
	if c.GetPeer() != "" {
		opts.peerAddr = c.GetPeer()
	}
	opts.vklink = c.GetVkLink()
	opts.vklinkSecondary = c.GetVkLinkSecondary()
	if c.GetListen() != "" {
		opts.listen = c.GetListen()
	}
	if c.GetThreads() > 0 {
		opts.n = int(c.GetThreads())
	}
	if c.GetCredsGroupSize() > 0 {
		opts.credsGroupSize = int(c.GetCredsGroupSize())
	}
	if c.GetTransport() != "" {
		opts.transport = c.GetTransport()
	}
	opts.udp = c.GetUdp()
	opts.direct = c.GetNoDtls()
	opts.manualCaptcha = c.GetManualCaptcha()
	if c.GetCaptchaSolver() != "" {
		opts.captchaSolver = c.GetCaptchaSolver()
	}
	if c.GetVkAuth() != "" {
		opts.vkAuth = c.GetVkAuth()
	}
	opts.vkSessionFile = c.GetVkSessionFile()
	opts.vkCookieFilePoll = c.GetVkCookieFilePoll()
	if c.GetSessionMode() != "" {
		opts.sessionMode = c.GetSessionMode()
	}
	if c.GetBrowserFp() != "" {
		opts.browserFP = c.GetBrowserFp()
	}
	opts.host = c.GetTurnHost()
	opts.port = c.GetTurnPort()
	opts.protectSock = c.GetProtectSock()
	if c.GetWrapMode() != "" {
		opts.wrapMode = c.GetWrapMode()
	}
	if c.GetWrapCipher() != "" {
		opts.wrapCipher = c.GetWrapCipher()
	}
	opts.wrapKeyHex = c.GetWrapKeyHex()
	opts.wrapSendKey = c.GetWrapSendKey()
	opts.protoFingerprint = c.GetProtoFp()
	// Announce the managed client id in mu SESSION hellos so the node can echo this
	// client's traffic-limit usage back in the heartbeat. Empty for anonymous.
	sessionmuv1.SetSessionClientID(c.GetClientId())
}

func main() { //nolint:cyclop
	opts, exitCode := parseClientOptions(os.Args[1:], filepath.Base(os.Args[0]), os.Stdout, os.Stderr)
	if exitCode != 0 && exitCode != -1 {
		os.Exit(exitCode)
	}
	if exitCode == 0 {
		os.Exit(0)
	}
	log.Printf("WINGS V VK TURN PROXY client %s starting", clientVersion)
	// Cache the physical egress interface now, before any tunnel exists (Windows underlay
	// bypass); off Windows this is a no-op.
	initBypass()
	applyUserDns(opts.userDns)
	setDnsMode(opts.dnsMode)
	log.Printf("[DNS] mode=%s", dnsMode())
	setBrowserFamily(opts.browserFP)
	log.Printf("[FP] browser=%s", browserFamily)

	if opts.roomExchangeMode {
		if err := runRoomExchangeMode(opts); err != nil {
			log.Fatalf("room-exchange: %v", err)
		}
		return
	}
	if opts.wbStreamRoomID != "" || opts.wbStreamRoomIDs != "" {
		if err := runWbStreamClient(opts); err != nil {
			log.Fatalf("wb-stream client: %v", err)
		}
		return
	}

	ctx, cancel := context.WithCancel(context.Background())
	globalAppCancel = cancel
	defer cancel()
	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, syscall.SIGTERM, syscall.SIGINT)
	go func() {
		<-signalChan
		log.Printf("Terminating...\n")
		cancel()
		select {
		case <-signalChan:
		case <-time.After(5 * time.Second):
		}
		log.Fatalf("Exit...\n")
	}()

	// gRPC-config bootstrap: the host app launches the relay with only the
	// AppControl socket flags and delivers the runtime configuration over the
	// Configure RPC. Start AppControl first, then block for Configure before the
	// engine (protect bridge, resolver, TURN) is built from opts.
	if opts.appGRPCSocket != "" {
		if _, startErr := StartAppControl(opts.appGRPCSocket, opts.appGRPCToken, opts.appGRPCPeerUID, opts.appGRPCPeerContext, setVkCookies, provisionViaWorker, receiveConfigure); startErr != nil {
			log.Printf("app-control: %v", startErr)
		} else {
			log.Printf("app-control: serving on %s", opts.appGRPCSocket)
		}
		if opts.peerAddr == "" && opts.vklink == "" {
			log.Printf("app-control: awaiting Configure over gRPC...")
			cfg := awaitConfigure(ctx)
			if cfg == nil {
				log.Fatalf("app-control: no Configure received before timeout")
			}
			applyConfigureToOptions(&opts, cfg)
			applyUserDns(opts.userDns)
			setDnsMode(opts.dnsMode)
			setBrowserFamily(opts.browserFP)
			manualCaptcha = opts.manualCaptcha
			captchaSolverVersion = opts.captchaSolver
			log.Printf("[DNS] mode=%s (gRPC)", dnsMode())
			log.Printf("[FP] browser=%s (gRPC)", browserFamily)
		}
	}

	peerResolver := (*protectedResolver)(nil)
	protect, err := newProtectBridge(opts.protectSock)
	if err != nil {
		log.Panicf("Failed to connect protect bridge: %s", err)
	}
	if protect != nil {
		defer func() {
			if closeErr := protect.Close(); closeErr != nil {
				log.Printf("Failed to close protect bridge: %s", closeErr)
			}
		}()
	}
	peerResolver = newProtectedResolver(protect, defaultResolverAddrs)
	manualCaptcha = opts.manualCaptcha
	captchaSolverVersion = opts.captchaSolver
	setVkAuthMode(opts.vkAuth)
	if getVkAuthMode() == "account" {
		log.Printf("[VK Auth] account mode armed")
		// Persist + restore the VK session across relay restarts so a restart does
		// not force the host app to re-deliver cookies.
		setVkSessionFile(opts.vkSessionFile)
		loadVkSessionFromFile()
		if opts.vkCookieFilePoll {
			// Root/kernel-WG path: the host app delivers cookies by writing the
			// session file (stdin is not writable under su -c), so watch it live.
			startVkSessionFilePoll(ctx)
		}
		// Read account creds delivered by the host app on stdin (account mode only).
		StartAccountCredsStdinReader(ctx)
	}
	setTcpFlavorOverride(opts.tcpFlavor)
	_ = strings.TrimSpace(opts.protoFingerprint)
	emitProxyCaps()

	requestedTransport, err := parseRequestedTransport(opts.transport, opts.vlessMode)
	if err != nil {
		log.Panicf("Invalid transport mode: %v", err)
	}

	peer, err := peerResolver.ResolveUDPAddrPreferIPv4(ctx, opts.peerAddr)
	if err != nil {
		panic(err)
	}
	reportUnderlayDest(peer.String()) // Windows: physical bypass route for the peer server
	requestedSessionMode, err := sessionproto.ParseMode(opts.sessionMode)
	if err != nil {
		log.Panicf("Invalid session mode: %v", err)
	}

	var link string
	var unifiedGetCreds getCredsFunc
	var vkLinkManager *groupedCredsManager
	if opts.vklink != "" {
		rawEntries := strings.Split(opts.vklink, ",")
		extracted := make([]string, 0, len(rawEntries))
		for _, raw := range rawEntries {
			trimmed := strings.TrimSpace(raw)
			if trimmed == "" {
				continue
			}
			parts := strings.Split(trimmed, "join/")
			hash := parts[len(parts)-1]
			if idx := strings.IndexAny(hash, "/?#"); idx != -1 {
				hash = hash[:idx]
			}
			hash = normalizeJoinLink(hash)
			if hash != "" {
				extracted = append(extracted, hash)
			}
		}
		if len(extracted) == 0 {
			log.Panicf("invalid -vk-link: no usable entries parsed")
		}
		link = extracted[0]

		secondaryHash := ""
		if opts.vklinkSecondary != "" {
			secParts := strings.Split(opts.vklinkSecondary, "join/")
			h := secParts[len(secParts)-1]
			if idx := strings.IndexAny(h, "/?#"); idx != -1 {
				h = h[:idx]
			}
			secondaryHash = normalizeJoinLink(h)
		}

		if opts.n <= 0 {
			if requestedTransport == sessionproto.TransportMode_TRANSPORT_MODE_TCP {
				opts.n = 24
			} else {
				opts.n = 10
			}
		}
		if getVkAuthMode() == "account" && opts.n > accountMaxWorkers {
			log.Printf("[VK Auth] account mode: capping workers from %d to %d (account TURN quota is small)", opts.n, accountMaxWorkers)
			opts.n = accountMaxWorkers
		}

		tracker, err := newLinkHealthTracker(extracted, secondaryHash)
		if err != nil {
			log.Panicf("link tracker init: %v", err)
		}
		credsGroupSize := max(1, opts.credsGroupSize)
		numGroups := max(1, ceilDiv(opts.n, credsGroupSize))
		vkFetch := func(fctx context.Context, hash string, allowInteractive bool) (turnCred, error) {
			if getVkAuthMode() == "account" {
				user, pass, addrs, lifetime, err := getAccountVkCreds(fctx, hash, peerResolver)
				if err != nil {
					return turnCred{}, err
				}
				return turnCred{user: user, pass: pass, addrs: addrs, lifetime: lifetime}, nil
			}
			user, pass, addrs, lifetime, err := getVkCredsWithFallback(hash, peerResolver, allowInteractive)
			if err != nil {
				return turnCred{}, err
			}
			return turnCred{user: user, pass: pass, addrs: addrs, lifetime: lifetime}, nil
		}
		vkLinkManager = newGroupedCredsManager(ctx, numGroups, credsGroupSize, tracker, vkFetch)
		// Expose the tracker for live VK-links patching.
		patchLinkTracker = tracker
		log.Printf(
			"VK creds: %d primary link(s), secondary=%t, %d groups × %d workers (n=%d)",
			len(extracted),
			secondaryHash != "",
			numGroups,
			credsGroupSize,
			opts.n,
		)
		unifiedGetCreds = vkLinkManager.GetCredsForWorker
	} else {
		parts := strings.Split(opts.yalink, "j/")
		link = parts[len(parts)-1]
		if idx := strings.IndexAny(link, "/?#"); idx != -1 {
			link = link[:idx]
		}
		link = normalizeJoinLink(link)
		if opts.n <= 0 {
			opts.n = 1
		}
		yandexBase := func(s string, _ bool) (string, string, []string, time.Duration, error) {
			user, pass, addr, err := getYandexCreds(s, peerResolver)
			if err != nil {
				return "", "", nil, 0, err
			}
			return user, pass, []string{addr}, 0, nil
		}
		yandexPool := poolCreds(yandexBase, 1)
		yandexLink := link
		unifiedGetCreds = func(workerID int) (string, string, string, error) {
			return yandexPool(yandexLink, workerID)
		}
	}
	configuredPoolSize := max(1, opts.n)
	effectiveStreamCount := func(sessionMode sessionproto.Mode, protocolVersion uint32) int {
		_ = sessionMode
		_ = protocolVersion
		return configuredPoolSize
	}
	buildGetCreds := func(sessionMode sessionproto.Mode, protocolVersion uint32, effectiveCount int) getCredsFunc {
		_ = sessionMode
		_ = protocolVersion
		_ = effectiveCount
		return unifiedGetCreds
	}
	buildAutoGetCreds := func() (getCredsFunc, func(sessionproto.Mode, uint32, int)) {
		setStrategy := func(_ sessionproto.Mode, _ uint32, _ int) {}
		return unifiedGetCreds, setStrategy
	}
	wrapCipherSel, wrapKey, wrapMode, err := resolveWrapConfig(opts.wrapMode, opts.wrapCipher, opts.wrapKeyHex)
	if err != nil {
		log.Panicf("WRAP config: %v", err)
	}
	recycleConcurrency := opts.n * recycleConcurrencyPercent / 100
	if recycleConcurrency < 1 {
		recycleConcurrency = 1
	}
	params := &turnParams{
		host:         opts.host,
		port:         opts.port,
		link:         link,
		udp:          opts.udp,
		getCreds:     nil,
		resolver:     peerResolver,
		credsManager: vkLinkManager,
		wrapCipher:   wrapCipherSel,
		wrapKey:      wrapKey,
		wrapMode:     wrapMode,
		wrapSendKey:  opts.wrapSendKey,
		wrapStates:   &sync.Map{},
		recycleGate:  make(chan struct{}, recycleConcurrency),
	}
	// Seed the live snapshot from the boot config; PatchConfig swaps it later.
	patchResolver = peerResolver
	liveCfg.Store(&liveSnapshot{
		host:        opts.host,
		port:        opts.port,
		peer:        peer,
		wrapCipher:  wrapCipherSel,
		wrapKey:     wrapKey,
		wrapMode:    wrapMode,
		wrapSendKey: opts.wrapSendKey,
	})
	sessionID := []byte(nil)

	if requestedTransport == sessionproto.TransportMode_TRANSPORT_MODE_TCP {
		if opts.direct {
			log.Panicf("TCP transport does not support -no-dtls")
		}
		if requestedSessionMode == sessionproto.ModeMu {
			log.Panicf("transport=tcp is not supported with session-mode=mu")
		}
		effectiveCount := effectiveStreamCount(sessionproto.ModeMainline, muProtocolNone)
		params.getCreds = buildGetCreds(sessionproto.ModeMainline, muProtocolNone, effectiveCount)
		log.Printf("Transport mode: tcp")
		runTCPMode(ctx, params, peer, opts.listen, opts.n)
		return
	}

	listenConn, err := net.ListenPacket("udp", opts.listen) // nolint: noctx
	if err != nil {
		log.Panicf("Failed to listen: %s", err)
	}
	tuneUDPBuffers(listenConn, "local listen")
	context.AfterFunc(ctx, func() {
		if closeErr := listenConn.Close(); closeErr != nil {
			log.Panicf("Failed to close local connection: %s", closeErr)
		}
	})

	wg1 := sync.WaitGroup{}
	t := time.Tick(200 * time.Millisecond)
	if opts.direct {
		listenConnChan := make(chan net.PacketConn)
		go func() {
			for {
				select {
				case <-ctx.Done():
					return
				case listenConnChan <- listenConn:
				}
			}
		}()
		params.getCreds = unifiedGetCreds
		for i := 0; i < opts.n; i++ {
			streamID := i
			wg1.Go(func() {
				oneTurnConnectionLoop(ctx, params, peer, listenConnChan, t, streamID, nil, false, true)
			})
		}
	} else {
		inboundChan := make(chan *UDPPacket, inboundPacketQueueSize)
		go func() {
			for {
				pktIface := packetPool.Get()
				pkt, ok := pktIface.(*UDPPacket)
				if !ok {
					log.Printf("packetPool returned unexpected type: %T", pktIface)
					continue
				}
				nRead, addr, readErr := listenConn.ReadFrom(pkt.Data)
				if readErr != nil {
					packetPool.Put(pkt)
					return
				}
				current := activeLocalPeer.Load()
				if current == nil {
					activeLocalPeer.Store(addr)
					log.Printf("[local] first WG packet from %s (%d bytes) - forwarding into tunnel", addr, nRead)
				} else if currentAddr, ok := current.(net.Addr); !ok || currentAddr.String() != addr.String() {
					activeLocalPeer.Store(addr)
				}
				pkt.N = nRead
				select {
				case inboundChan <- pkt:
				default:
					packetPool.Put(pkt)
				}
			}
		}()
		type muProbeSelection struct {
			version            uint32
			sessionID          []byte
			heartbeatSupported bool
		}
		probeMuCompatibility := func(control *mainlineControlHandle, candidateVersion uint32) *muProbeSelection {
			probeSessionID := resolveSessionID(sessionproto.ModeMu, opts.sessionID)
			log.Printf(
				"Compatibility probe: testing mu/v%d session hello, session ID: %s",
				candidateVersion,
				hex.EncodeToString(probeSessionID),
			)
			hello, err := buildSessionHelloForVersion(candidateVersion, probeSessionID, 0)
			if err != nil {
				log.Printf("Compatibility probe: failed to build mu/v%d session hello: %s", candidateVersion, err)
				return nil
			}
			serverHello, err := exchangeMuSessionHelloOnActiveMainline(control, hello, candidateVersion)
			if err == nil && serverHello.GetMuSupported() {
				log.Printf("Compatibility probe: mu/v%d session hello acknowledged", candidateVersion)
				return &muProbeSelection{
					version:            candidateVersion,
					sessionID:          append([]byte(nil), probeSessionID...),
					heartbeatSupported: serverHello.GetControlHeartbeatSupported(),
				}
			}
			if err != nil {
				log.Printf("Compatibility probe: mu/v%d session hello was not acknowledged: %s", candidateVersion, err)
				return nil
			}
			if serverHello.GetError() != "" {
				log.Printf("Compatibility probe: mu/v%d rejected by server: %s", candidateVersion, serverHello.GetError())
			} else {
				log.Printf("Compatibility probe: mu/v%d session hello was not acknowledged", candidateVersion)
			}
			return nil
		}
		buildSessionRuntime := func(
			runtimeCtx context.Context,
			sessionMode sessionproto.Mode,
			protocolVersion uint32,
			sessionID []byte,
			statusEnabled bool,
		) *sessionRuntime {
			runtime := newSessionRuntime(runtimeCtx, sessionMode, protocolVersion, sessionID, statusEnabled, nil)
			runtime.AttachCredsManager(vkLinkManager)
			return runtime
		}

		runtimeCtx, runtimeCancel := context.WithCancel(ctx)
		defer func() {
			runtimeCancel()
		}()
		runtimeWG := (*sync.WaitGroup)(nil)

		switch requestedSessionMode {
		case sessionproto.ModeMainline:
			effectiveCount := effectiveStreamCount(sessionproto.ModeMainline, muProtocolNone)
			params.getCreds = buildGetCreds(sessionproto.ModeMainline, muProtocolNone, effectiveCount)
			okchan := make(chan struct{}, 1)
			runtime := buildSessionRuntime(runtimeCtx, sessionproto.ModeMainline, muProtocolNone, nil, true)
			runtimeWG = startDtlsTurnWorkers(
				runtimeCtx,
				peer,
				listenConn,
				inboundChan,
				params,
				t,
				effectiveCount,
				sessionproto.ModeMainline,
				nil,
				muProtocolNone,
				okchan,
				nil,
				nil,
				runtime,
				false,
				true,
			)
		case sessionproto.ModeMu:
			upgraded := false
			for _, candidateVersion := range []uint32{muProtocolV1} {
				effectiveCount := effectiveStreamCount(sessionproto.ModeMu, candidateVersion)
				sessionID = resolveSessionID(sessionproto.ModeMu, opts.sessionID)
				params.getCreds = buildGetCreds(sessionproto.ModeMu, candidateVersion, effectiveCount)
				log.Printf("Session mode: mu/v%d, session ID: %s", candidateVersion, hex.EncodeToString(sessionID))

				okchan := make(chan struct{})
				runtime := buildSessionRuntime(runtimeCtx, sessionproto.ModeMu, candidateVersion, sessionID, true)
				runtimeWG = startDtlsTurnWorkers(
					runtimeCtx,
					peer,
					listenConn,
					inboundChan,
					params,
					t,
					effectiveCount,
					sessionproto.ModeMu,
					sessionID,
					candidateVersion,
					okchan,
					nil,
					nil,
					runtime,
					false,
					true,
				)
				if waitForReady(ctx, okchan, muReadyTimeout) {
					upgraded = true
					break
				}

				log.Printf("Session mode: mu/v%d failed, retrying fallback", candidateVersion)
				runtimeCancel()
				runtimeWG.Wait()
				runtimeCtx, runtimeCancel = context.WithCancel(ctx)
			}

			if !upgraded {
				log.Printf("Session mode: mu fallback -> mainline")
				effectiveCount := effectiveStreamCount(sessionproto.ModeMainline, muProtocolNone)
				params.getCreds = buildGetCreds(sessionproto.ModeMainline, muProtocolNone, effectiveCount)
				okchan := make(chan struct{}, 1)
				runtime := buildSessionRuntime(runtimeCtx, sessionproto.ModeMainline, muProtocolNone, nil, true)
				runtimeWG = startDtlsTurnWorkers(
					runtimeCtx,
					peer,
					listenConn,
					inboundChan,
					params,
					t,
					effectiveCount,
					sessionproto.ModeMainline,
					nil,
					muProtocolNone,
					okchan,
					nil,
					nil,
					runtime,
					false,
					true,
				)
			}
		case sessionproto.ModeAuto:
			okchan := make(chan struct{})
			probeResult := make(chan uint32, 1)
			mainlineControl := make(chan *mainlineControlHandle, 1)
			autoGetCreds, setAutoPoolStrategy := buildAutoGetCreds()
			setAutoPoolStrategy(sessionproto.ModeMainline, muProtocolNone, 1)
			params.getCreds = autoGetCreds
			runtime := buildSessionRuntime(runtimeCtx, sessionproto.ModeMainline, muProtocolNone, nil, false)
			runtimeWG = startDtlsTurnWorkers(
				runtimeCtx,
				peer,
				listenConn,
				inboundChan,
				params,
				t,
				1,
				sessionproto.ModeMainline,
				nil,
				muProtocolNone,
				okchan,
				probeResult,
				mainlineControl,
				runtime,
				true,
				false,
			)
			if !waitForReady(ctx, okchan, mainlineBootstrapTimeout) {
				runtimeCancel()
				runtimeWG.Wait()
				log.Fatalf("failed to bootstrap mainline session")
			}

			supportedVersion := waitForProbeVersion(ctx, probeResult, muProbeTimeout)
			activeMainlineControl := waitForMainlineControlHandle(ctx, mainlineControl, muProbeTimeout)
			candidateVersions := make([]uint32, 0, 1)
			switch supportedVersion {
			case muProtocolV1:
				candidateVersions = append(candidateVersions, muProtocolV1)
			}

			selectedMu := (*muProbeSelection)(nil)
			for _, candidateVersion := range candidateVersions {
				if selection := probeMuCompatibility(activeMainlineControl, candidateVersion); selection != nil {
					selectedMu = selection
					break
				}
			}

			runtimeCancel()
			runtimeWG.Wait()

			if selectedMu == nil {
				effectiveCount := effectiveStreamCount(sessionproto.ModeMainline, muProtocolNone)
				setAutoPoolStrategy(sessionproto.ModeMainline, muProtocolNone, effectiveCount)
				params.getCreds = autoGetCreds
				if len(candidateVersions) > 0 {
					log.Printf("Session mode: mu compatibility failed, restarting on clean mainline")
				} else {
					log.Printf("Session mode: staying on mainline")
				}
				runtimeCtx, runtimeCancel = context.WithCancel(ctx)
				okchan = make(chan struct{}, 1)
				runtime = buildSessionRuntime(runtimeCtx, sessionproto.ModeMainline, muProtocolNone, nil, true)
				runtimeWG = startDtlsTurnWorkers(
					runtimeCtx,
					peer,
					listenConn,
					inboundChan,
					params,
					t,
					effectiveCount,
					sessionproto.ModeMainline,
					nil,
					muProtocolNone,
					okchan,
					nil,
					nil,
					runtime,
					false,
					true,
				)
			} else {
				effectiveCount := effectiveStreamCount(sessionproto.ModeMu, selectedMu.version)
				sessionID = selectedMu.sessionID
				setAutoPoolStrategy(sessionproto.ModeMu, selectedMu.version, effectiveCount)
				params.getCreds = autoGetCreds
				log.Printf(
					"Session mode: mainline -> mu/v%d, session ID: %s",
					selectedMu.version,
					hex.EncodeToString(sessionID),
				)
				runtimeCtx, runtimeCancel = context.WithCancel(ctx)
				okchan = make(chan struct{})
				runtime = buildSessionRuntime(runtimeCtx, sessionproto.ModeMu, selectedMu.version, sessionID, true)
				runtimeWG = startDtlsTurnWorkers(
					runtimeCtx,
					peer,
					listenConn,
					inboundChan,
					params,
					t,
					effectiveCount,
					sessionproto.ModeMu,
					sessionID,
					selectedMu.version,
					okchan,
					nil,
					nil,
					runtime,
					false,
					true,
				)
				if !waitForReady(ctx, okchan, muReadyTimeout) {
					log.Printf("Session mode: mu/v%d failed after compatibility probe, falling back to clean mainline", selectedMu.version)
					runtimeCancel()
					runtimeWG.Wait()

					runtimeCtx, runtimeCancel = context.WithCancel(ctx)
					effectiveCount = effectiveStreamCount(sessionproto.ModeMainline, muProtocolNone)
					setAutoPoolStrategy(sessionproto.ModeMainline, muProtocolNone, effectiveCount)
					params.getCreds = autoGetCreds
					okchan = make(chan struct{}, 1)
					runtime = buildSessionRuntime(runtimeCtx, sessionproto.ModeMainline, muProtocolNone, nil, true)
					runtimeWG = startDtlsTurnWorkers(
						runtimeCtx,
						peer,
						listenConn,
						inboundChan,
						params,
						t,
						effectiveCount,
						sessionproto.ModeMainline,
						nil,
						muProtocolNone,
						okchan,
						nil,
						nil,
						runtime,
						false,
						true,
					)
				}
			}
		}

		wg1.Go(func() {
			runtimeWG.Wait()
		})
	}

	wg1.Wait()
}
