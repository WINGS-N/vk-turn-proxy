// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package main

import (
	"context"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net"
	"net/http"
	neturl "net/url"
	"os"
	"os/signal"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/cacggghp/vk-turn-proxy/sessionproto"
	"github.com/cbeuw/connutil"
	"github.com/google/uuid"
	"github.com/pion/dtls/v3"
	"github.com/pion/dtls/v3/pkg/crypto/selfsign"
	"github.com/pion/logging"
	"github.com/pion/transport/v4"
	"github.com/pion/turn/v5"
)

type getCredsFunc func(string) (string, string, string, error)

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

var packetPool = sync.Pool{
	New: func() any { return &UDPPacket{Data: make([]byte, 2048)} },
}

func newDirectNet() transport.Net {
	return directNet{}
}

func (directNet) ListenPacket(network string, address string) (net.PacketConn, error) {
	return net.ListenPacket(network, address)
}

func (directNet) ListenUDP(network string, locAddr *net.UDPAddr) (transport.UDPConn, error) {
	return net.ListenUDP(network, locAddr)
}

func (directNet) ListenTCP(network string, laddr *net.TCPAddr) (transport.TCPListener, error) {
	listener, err := net.ListenTCP(network, laddr)
	if err != nil {
		return nil, err
	}

	return directTCPListener{listener}, nil
}

func (directNet) Dial(network, address string) (net.Conn, error) {
	return net.Dial(network, address)
}

func (directNet) DialUDP(network string, laddr, raddr *net.UDPAddr) (transport.UDPConn, error) {
	return net.DialUDP(network, laddr, raddr)
}

func (directNet) DialTCP(network string, laddr, raddr *net.TCPAddr) (transport.TCPConn, error) {
	return net.DialTCP(network, laddr, raddr)
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
	activeLocalPeer      atomic.Value
	manualCaptcha        bool
	globalCaptchaLockout atomic.Int64
	connectedStreams     atomic.Int32
	globalAppCancel      context.CancelFunc
	proxyAuthReadyState  atomic.Bool
	proxyTurnReadyState  atomic.Bool
	proxyDtlsReadyState  atomic.Bool
	protoFingerprint     string
	handshakeSem         = make(chan struct{}, 3)
	cachedCaptchaTokenMu sync.Mutex
	cachedCaptchaToken   string
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

func getVkCredsWithFallback(link string, resolver *protectedResolver, allowInteractiveFallback bool) (string, string, string, error) {
	if remaining := captchaLockoutRemaining(); remaining > 0 {
		emitCaptchaLockoutStatus(remaining)
		return "", "", "", fmt.Errorf("CAPTCHA_WAIT_REQUIRED: global lockout active for %s", remaining.Round(time.Second))
	}

	profile := getRandomProfile()
	name := generateName()
	escapedName := neturl.QueryEscape(name)
	client, err := resolver.newTLSHTTPClient(profile, 20*time.Second)
	if err != nil {
		return "", "", "", fmt.Errorf("failed to initialize tls client: %w", err)
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
		req.Header.Set("Origin", "https://vk.ru")
		req.Header.Set("Referer", "https://vk.ru/")
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

	data := "client_id=6287487&token_type=messages&client_secret=QbYic1K3lEV5kTGiqlq2&version=1&app_id=6287487"
	url := "https://login.vk.ru/?act=get_anonym_token"

	resp, err = doRequest(data, url)
	if err != nil {
		return "", "", "", fmt.Errorf("request error:%s", err)
	}

	dataMap, ok := resp["data"].(map[string]interface{})
	if !ok {
		return "", "", "", fmt.Errorf("unexpected anon token response: %v", resp)
	}
	token1, ok := dataMap["access_token"].(string)
	if !ok {
		return "", "", "", fmt.Errorf("missing access_token in response: %v", resp)
	}

	vkDelayRandom(100, 150)
	previewData := fmt.Sprintf("vk_join_link=https://vk.com/call/join/%s&fields=photo_200&access_token=%s", link, token1)
	_, _ = doRequest(previewData, "https://api.vk.ru/method/calls.getCallPreview?v=5.275&client_id=6287487")
	vkDelayRandom(200, 400)

	data = fmt.Sprintf("vk_join_link=https://vk.com/call/join/%s&name=%s&access_token=%s", link, escapedName, token1)
	if cachedSuccessToken := loadCachedCaptchaToken(); cachedSuccessToken != "" {
		log.Printf("Reusing cached VK success_token for auth warmup")
		data += fmt.Sprintf("&success_token=%s", neturl.QueryEscape(cachedSuccessToken))
	}
	url = "https://api.vk.ru/method/calls.getAnonymousToken?v=5.275&client_id=6287487"

	var token2 string
	const maxCaptchaAttempts = 3
	usedAutoCaptcha := false
	for attempt := 0; attempt <= maxCaptchaAttempts; attempt++ {
		resp, err = doRequest(data, url)
		if err != nil {
			return "", "", "", fmt.Errorf("request error:%s", err)
		}

		if errObj, hasErr := resp["error"].(map[string]interface{}); hasErr {
			errCode, _ := errObj["error_code"].(float64)
			if errCode == 14 {
				if attempt == maxCaptchaAttempts {
					return "", "", "", wrapCaptchaFailure(fmt.Errorf("captcha failed after %d attempts", maxCaptchaAttempts), allowInteractiveFallback)
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
						successToken, solveErr = solveVkCaptcha(
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
						return "", "", "", wrapCaptchaFailure(fmt.Errorf("smart captcha solve error: %w", solveErr), allowInteractiveFallback)
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
							return "", "", "", wrapCaptchaFailure(fmt.Errorf("captcha solve error: %w", solveErr), false)
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
						return "", "", "", wrapCaptchaFailure(fmt.Errorf("captcha solve error: %w", solveErr), true)
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
			return "", "", "", fmt.Errorf("VK API error: %v", errObj)
		}

		responseMap, ok := resp["response"].(map[string]interface{})
		if !ok {
			return "", "", "", fmt.Errorf("unexpected getAnonymousToken response: %v", resp)
		}
		token2, ok = responseMap["token"].(string)
		if !ok {
			return "", "", "", fmt.Errorf("missing token in response: %v", resp)
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
		return "", "", "", fmt.Errorf("request error:%s", err)
	}

	token3 := resp["session_key"].(string)

	vkDelayRandom(100, 150)
	data = fmt.Sprintf("joinLink=%s&isVideo=false&protocolVersion=5&capabilities=2F7F&anonymToken=%s&method=vchat.joinConversationByLink&format=JSON&application_key=CGMMEJLGDIHBABABA&session_key=%s", link, token2, token3)
	url = "https://calls.okcdn.ru/fb.do"

	resp, err = doRequest(data, url)
	if err != nil {
		return "", "", "", fmt.Errorf("request error:%s", err)
	}

	user := resp["turn_server"].(map[string]interface{})["username"].(string)
	pass := resp["turn_server"].(map[string]interface{})["credential"].(string)
	turn := resp["turn_server"].(map[string]interface{})["urls"].([]interface{})[0].(string)

	clean := strings.Split(turn, "?")[0]
	address := strings.TrimPrefix(strings.TrimPrefix(clean, "turn:"), "turns:")

	return user, pass, address, nil
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
		Uid string `json:"uid"`
		Ack struct {
			Status struct {
				Code string `json:"code"`
			} `json:"status"`
		} `json:"ack"`
	}

	type WSSData struct {
		ParticipantId string
		RoomId        string
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
		body, _ := io.ReadAll(resp.Body)
		return "", "", "", fmt.Errorf("GetConference: status=%s body=%s", resp.Status, string(body))
	}

	var result ConferenceResponse
	if err = json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", "", "", fmt.Errorf("decode conf: %v", err)
	}
	data := WSSData{
		ParticipantId: result.PeerID,
		RoomId:        result.RoomID,
		Credentials:   result.Credentials,
		Wss:           result.ClientConfiguration.MediaServerURL,
	}
	h := http.Header{}
	h.Set("Origin", "https://telemost.yandex.ru")
	applyBrowserProfile(&http.Request{Header: h}, profile)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	dialer := resolver.newWebsocketDialer(15 * time.Second)
	conn, _, err := dialer.DialContext(ctx, data.Wss, h)
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

			ParticipantID: data.ParticipantId,
			RoomID:        data.RoomId,
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
	config := &dtls.Config{
		Certificates:          []tls.Certificate{certificate},
		InsecureSkipVerify:    true,
		ExtendedMasterSecret:  dtls.RequireExtendedMasterSecret,
		CipherSuites:          []dtls.CipherSuiteID{dtls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256},
		ConnectionIDGenerator: dtls.OnlySendCIDGenerator(),
	}
	dtlsConn, err := dtls.Client(conn, peer, config)
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
	probeOnly bool,
) *sync.WaitGroup {
	wg := &sync.WaitGroup{}
	connchan := make(chan net.PacketConn)
	delayAdditionalWorkers := sessionMode == sessionproto.ModeMainline && !probeOnly && firstReady != nil

	wg.Go(func() {
		oneDtlsConnectionLoop(
			ctx,
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
			0,
			probeOnly,
		)
	})
	wg.Go(func() {
		oneTurnConnectionLoop(ctx, params, peer, connchan, t, 0, probeOnly)
	})

	spawnAdditionalWorkers := func() {
		for i := 0; i < n-1; i++ {
			connchan := make(chan net.PacketConn)
			streamID := byte(i + 1)
			wg.Go(func() {
				oneDtlsConnectionLoop(
					ctx,
					peer,
					listenConn,
					inboundChan,
					connchan,
					nil,
					nil,
					nil,
					sessionMode,
					sessionID,
					protocolVersion,
					streamID,
					probeOnly,
				)
			})
			wg.Go(func() {
				oneTurnConnectionLoop(ctx, params, peer, connchan, t, int(streamID), probeOnly)
			})
		}
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

func oneDtlsConnection(
	ctx context.Context,
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
	probeOnly bool,
) {
	time.Sleep(time.Duration(rand.Intn(400)+100) * time.Millisecond)
	var err error = nil
	defer func() { c <- err }()
	dtlsctx, dtlscancel := context.WithCancel(ctx)
	defer dtlscancel()
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
	dtlsConn, err1 := dtlsFunc(dtlsctx, conn1, peer)
	if err1 != nil {
		err = fmt.Errorf("failed to connect DTLS: %s", err1)
		return
	}
	defer func() {
		if closeErr := dtlsConn.Close(); closeErr != nil {
			err = fmt.Errorf("failed to close DTLS connection: %s", closeErr)
			return
		}
		log.Printf("Closed DTLS connection\n")
	}()
	dtlsWriteMu := &sync.Mutex{}
	controlResponses := make(chan []byte, 4)
	sessionResponses := make(chan []byte, 4)
	var expectRawSessionHello atomic.Bool
	controlHeartbeatSupported := false
	if sessionMode == sessionproto.ModeMux {
		hello, err1 := buildSessionHelloForVersion(protocolVersion, sessionID, streamID)
		if err1 != nil {
			err = fmt.Errorf("failed to build session hello: %s", err1)
			return
		}
		serverHello, err1 := exchangeMuxSessionHello(dtlsConn, hello, protocolVersion)
		if err1 != nil {
			err = fmt.Errorf("failed to complete mux negotiation: %s", err1)
			return
		}
		if !serverHello.GetMuxSupported() {
			if serverHello.GetError() != "" {
				err = fmt.Errorf("server rejected mux negotiation: %s", serverHello.GetError())
			} else {
				err = fmt.Errorf("server rejected mux negotiation")
			}
			return
		}
		controlHeartbeatSupported = serverHello.GetControlHeartbeatSupported()
		log.Printf("Established DTLS connection and completed mux negotiation for stream %d!\n", streamID)
	} else {
		if probeOnly {
			log.Printf("Established DTLS probe connection!\n")
		} else {
			log.Printf("Established DTLS connection!\n")
		}
	}
	if sessionMode != sessionproto.ModeMux && streamID == 0 && mainlineControl != nil {
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
	if controlHeartbeatSupported && streamID == 0 {
		go startControlHeartbeatLoop(dtlsctx, dtlsConn, dtlsWriteMu)
	}
	if !probeOnly {
		emitProxyStatus("dtls_ready")
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
			log.Printf("Failed to set DTLS deadline: %s", err)
		}
	})
	if !probeOnly {
		go func() {
			defer dtlscancel()
			for {
				select {
				case <-dtlsctx.Done():
					return
				case pkt, ok := <-inboundChan:
					if !ok {
						return
					}
					dtlsWriteMu.Lock()
					_, err1 := dtlsConn.Write(pkt.Data[:pkt.N])
					dtlsWriteMu.Unlock()
					packetPool.Put(pkt)
					if err1 != nil {
						log.Printf("Failed: %s", err1)
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
				log.Printf("Failed: %s", err1)
				return
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
				if _, parseErr := sessionproto.ParseHeartbeatMessage(payload); parseErr != nil {
					log.Printf("Failed to parse control heartbeat response: %s", parseErr)
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
			addr1, ok := activeLocalPeer.Load().(net.Addr)
			if !ok {
				continue
			}

			_, err1 = listenConn.WriteTo(buf[:n], addr1)
			if err1 != nil {
				log.Printf("Failed: %s", err1)
				return
			}
		}
	}()
	if sessionMode != sessionproto.ModeMux && streamID == 0 && probeResult != nil {
		go func() {
			version, heartbeatSupported := negotiateMainlineFeatures(dtlsConn, dtlsWriteMu, controlResponses)
			select {
			case probeResult <- version:
			default:
			}
			if heartbeatSupported {
				go startControlHeartbeatLoop(dtlsctx, dtlsConn, dtlsWriteMu)
			}
		}()
	}

	wg.Wait()
	if err := dtlsConn.SetDeadline(time.Time{}); err != nil {
		log.Printf("Failed to clear DTLS deadline: %s", err)
	}
}

type connectedUDPConn struct {
	*net.UDPConn
}

func (c *connectedUDPConn) WriteTo(p []byte, _ net.Addr) (int, error) {
	return c.Write(p)
}

type turnParams struct {
	host     string
	port     string
	link     string
	udp      bool
	getCreds getCredsFunc
	resolver *protectedResolver
}

func oneTurnConnection(
	ctx context.Context,
	turnParams *turnParams,
	peer *net.UDPAddr,
	conn2 net.PacketConn,
	streamID int,
	c chan<- error,
	probeOnly bool,
) {
	time.Sleep(time.Duration(rand.Intn(400)+100) * time.Millisecond)
	var err error = nil
	defer func() { c <- err }()
	defer func() {
		_ = conn2.Close()
	}()
	user, pass, url, err1 := turnParams.getCreds(turnParams.link)
	if err1 != nil {
		err = fmt.Errorf("failed to get TURN credentials: %s", err1)
		return
	}
	if !probeOnly {
		emitProxyStatus("auth_ready")
	}
	urlhost, urlport, err1 := net.SplitHostPort(url)
	if err1 != nil {
		err = fmt.Errorf("failed to parse TURN server address: %s", err1)
		return
	}
	if turnParams.host != "" {
		urlhost = turnParams.host
	}
	if turnParams.port != "" {
		urlport = turnParams.port
	}
	var turnServerAddr string
	turnServerAddr = net.JoinHostPort(urlhost, urlport)
	turnServerUdpAddr, err1 := turnParams.resolver.ResolveUDPAddr(ctx, turnServerAddr)
	if err1 != nil {
		err = fmt.Errorf("failed to resolve TURN server address: %s", err1)
		return
	}
	turnServerAddr = turnServerUdpAddr.String()
	// Dial TURN Server
	var cfg *turn.ClientConfig
	var turnConn net.PacketConn
	d := turnParams.resolver.dialer()
	ctx1, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if turnParams.udp {
		rawConn, err2 := d.DialContext(ctx1, "udp", turnServerAddr)
		if err2 != nil {
			err = fmt.Errorf("failed to connect to TURN server: %s", err2)
			return
		}
		conn, ok := rawConn.(*net.UDPConn)
		if !ok {
			_ = rawConn.Close()
			err = fmt.Errorf("failed to cast protected UDP connection")
			return
		}
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
			err = fmt.Errorf("failed to connect to TURN server: %s", err2)
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
		LoggerFactory:          logging.NewDefaultLoggerFactory(),
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
		err = fmt.Errorf("failed to listen: %s", err1)
		return
	}

	// Allocate a relay socket on the TURN server. On success, it
	// will return a net.PacketConn which represents the remote
	// socket.
	relayConn, err1 := client.Allocate()
	if err1 != nil {
		err = fmt.Errorf("failed to allocate: %s", err1)
		return
	}
	connectedStreams.Add(1)
	defer func() {
		connectedStreams.Add(-1)
		if err1 := relayConn.Close(); err1 != nil {
			err = fmt.Errorf("failed to close TURN allocated connection: %s", err1)
		}
	}()

	// The relayConn's local address is actually the transport
	// address assigned on the TURN server.
	log.Printf("[STREAM %d] relayed-address=%s", streamID, relayConn.LocalAddr().String())
	if !probeOnly {
		emitProxyStatus("turn_ready")
	}

	wg := sync.WaitGroup{}
	wg.Add(2)
	turnctx, turncancel := context.WithCancel(ctx)
	context.AfterFunc(turnctx, func() {
		if err := relayConn.SetDeadline(time.Now()); err != nil {
			log.Printf("Failed to set relay deadline: %s", err)
		}
		if err := conn2.SetDeadline(time.Now()); err != nil {
			log.Printf("Failed to set upstream deadline: %s", err)
		}
	})
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
				log.Printf("Failed: %s", err1)
				return
			}

			addr.Store(addr1) // store peer

			_, err1 = relayConn.WriteTo(buf[:n], peer)
			if err1 != nil {
				log.Printf("Failed: %s", err1)
				return
			}
		}
	}()

	// Start read-loop on relayConn
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
			n, _, err1 := relayConn.ReadFrom(buf)
			if err1 != nil {
				log.Printf("Failed: %s", err1)
				return
			}
			addr1, ok := addr.Load().(net.Addr)
			if !ok {
				continue
			}

			_, err1 = conn2.WriteTo(buf[:n], addr1)
			if err1 != nil {
				log.Printf("Failed: %s", err1)
				return
			}
		}
	}()

	wg.Wait()
	if err := relayConn.SetDeadline(time.Time{}); err != nil {
		log.Printf("Failed to clear relay deadline: %s", err)
	}
	if err := conn2.SetDeadline(time.Time{}); err != nil {
		log.Printf("Failed to clear upstream deadline: %s", err)
	}
}

func oneDtlsConnectionLoop(
	ctx context.Context,
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
	probeOnly bool,
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
			probeOnly,
		)
		if err := <-c; err != nil {
			log.Printf("%s; reconnecting in %s", err, workerReconnectBackoff)
		} else {
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
	probeOnly bool,
) {
	for {
		select {
		case <-ctx.Done():
			return
		case conn2 := <-connchan:
			select {
			case <-t:
				c := make(chan error)
				go oneTurnConnection(ctx, turnParams, peer, conn2, streamID, c, probeOnly)
				if err := <-c; err != nil {
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

func main() { //nolint:cyclop
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

	host := flag.String("turn", "", "override TURN server ip")
	port := flag.String("port", "", "override TURN port")
	listen := flag.String("listen", "127.0.0.1:9000", "listen on ip:port")
	vklink := flag.String("vk-link", "", "VK calls invite link \"https://vk.com/call/join/...\"")
	yalink := flag.String("yandex-link", "", "Yandex telemost invite link \"https://telemost.yandex.ru/j/...\"")
	peerAddr := flag.String("peer", "", "peer server address (host:port)")
	n := flag.Int("n", 0, "connections to TURN (default 10 for VK, 1 for Yandex)")
	transportFlag := flag.String("transport", "datagram", "transport mode: datagram|tcp")
	vlessModeFlag := flag.Bool("vless", false, "deprecated alias for -transport=tcp")
	udp := flag.Bool("udp", false, "connect to TURN with UDP")
	direct := flag.Bool("no-dtls", false, "connect without obfuscation. DO NOT USE")
	manualCaptchaFlag := flag.Bool("manual-captcha", false, "skip automatic captcha solving and use manual captcha flow immediately")
	protectSock := flag.String("protect-sock", "", "unix socket used for VpnService.protect fd bridge")
	protoFingerprintFlag := flag.String("proto-fp", "", "protocol fingerprint to include in heartbeat telemetry")
	sessionModeFlag := flag.String("session-mode", string(sessionproto.ModeAuto), "TURN session mode: mainline|mux|auto")
	sessionIDFlag := flag.String("session-id", "", "override session ID (hex, 32 chars) for mux mode")
	adaptivePoolMinFlag := flag.Int("adaptive-pool-min", 1, "minimum TURN identity pool size for mux protocol v3")
	adaptivePoolMaxFlag := flag.Int("adaptive-pool-max", 0, "maximum TURN identity pool size for mux protocol v3 (default: stream count)")
	adaptivePoolStreamsPerIdentityFlag := flag.Int("adaptive-pool-streams-per-id", defaultAdaptivePoolStreamsPerIdentity, "target concurrent streams per TURN identity for mux protocol v3")
	flag.Parse()
	if *peerAddr == "" {
		log.Panicf("Need peer address!")
	}
	peerResolver := (*protectedResolver)(nil)
	protect, err := newProtectBridge(*protectSock)
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
	manualCaptcha = *manualCaptchaFlag
	protoFingerprint = strings.TrimSpace(*protoFingerprintFlag)
	emitProxyCaps()

	peer, err := peerResolver.ResolveUDPAddr(ctx, *peerAddr)
	if err != nil {
		panic(err)
	}
	if (*vklink == "") == (*yalink == "") {
		log.Panicf("Need either vk-link or yandex-link!")
	}
	requestedSessionMode, err := sessionproto.ParseMode(*sessionModeFlag)
	if err != nil {
		log.Panicf("Invalid session mode: %v", err)
	}
	requestedTransport, err := parseRequestedTransport(*transportFlag, *vlessModeFlag)
	if err != nil {
		log.Panicf("Invalid transport mode: %v", err)
	}

	var link string
	var baseGetCreds pooledGetCredsFunc
	if *vklink != "" {
		parts := strings.Split(*vklink, "join/")
		link = parts[len(parts)-1]

		if *n <= 0 {
			if requestedTransport == sessionproto.TransportMode_TRANSPORT_MODE_TCP {
				*n = 16
			} else {
				*n = 10
			}
		}
		baseGetCreds = func(s string, allowInteractiveFallback bool) (string, string, string, error) {
			return getVkCredsWithFallback(s, peerResolver, allowInteractiveFallback)
		}
	} else {
		parts := strings.Split(*yalink, "j/")
		link = parts[len(parts)-1]
		if *n <= 0 {
			*n = 1
		}
		baseGetCreds = func(s string, _ bool) (string, string, string, error) {
			return getYandexCreds(s, peerResolver)
		}
	}
	configuredPoolSize := max(1, *n)
	effectiveStreamCount := func(sessionMode sessionproto.Mode, protocolVersion uint32) int {
		if sessionMode == sessionproto.ModeMainline {
			return 1
		}
		if sessionMode == sessionproto.ModeMux && protocolVersion != muxProtocolNone && protocolVersion < muxProtocolV3 {
			return 1
		}
		return configuredPoolSize
	}
	logLegacyMuxCompatibility := func(protocolVersion uint32, effectiveCount int) {
		if protocolVersion >= muxProtocolV3 || effectiveCount >= configuredPoolSize {
			return
		}
		if protocolVersion == muxProtocolNone {
			log.Printf(
				"Mainline datagram mode detected; forcing %d data stream for WireGuard compatibility",
				effectiveCount,
			)
			return
		}
		log.Printf(
			"Legacy mux v%d detected; forcing %d data stream for compatibility with older servers",
			protocolVersion,
			effectiveCount,
		)
	}
	buildGetCreds := func(sessionMode sessionproto.Mode, protocolVersion uint32, effectiveCount int) getCredsFunc {
		switch {
		case sessionMode == sessionproto.ModeMainline:
			log.Printf("TURN identity pool: fixed size 1 for mainline")
			return poolCreds(baseGetCreds, 1)
		case sessionMode == sessionproto.ModeMux && protocolVersion >= muxProtocolV3:
			adaptivePool := normalizeAdaptivePoolConfig(
				*adaptivePoolMinFlag,
				*adaptivePoolMaxFlag,
				*adaptivePoolStreamsPerIdentityFlag,
				effectiveCount,
			)
			log.Printf(
				"TURN identity pool: adaptive for mux v%d (min=%d max=%d streams_per_id=%d)",
				protocolVersion,
				adaptivePool.minSize,
				adaptivePool.maxSize,
				adaptivePool.streamsPerIdentity,
			)
			return poolCredsAdaptive(baseGetCreds, adaptivePool)
		default:
			log.Printf("TURN identity pool: fixed size %d", effectiveCount)
			return poolCreds(baseGetCreds, effectiveCount)
		}
	}
	buildAutoGetCreds := func() (getCredsFunc, func(sessionproto.Mode, uint32, int)) {
		var fixedPoolSize atomic.Int32
		var adaptiveEnabled atomic.Bool
		var adaptiveConfig atomic.Value
		adaptiveConfig.Store(normalizeAdaptivePoolConfig(1, 1, defaultAdaptivePoolStreamsPerIdentity, 1))

		targetPoolSize := func() int {
			if adaptiveEnabled.Load() {
				config, ok := adaptiveConfig.Load().(adaptivePoolConfig)
				if ok {
					return config.targetPoolSize()
				}
			}
			return max(1, int(fixedPoolSize.Load()))
		}

		setStrategy := func(sessionMode sessionproto.Mode, protocolVersion uint32, effectiveCount int) {
			switch {
			case sessionMode == sessionproto.ModeMainline:
				adaptiveEnabled.Store(false)
				fixedPoolSize.Store(1)
				log.Printf("TURN identity pool: fixed size 1 for mainline")
			case sessionMode == sessionproto.ModeMux && protocolVersion >= muxProtocolV3:
				config := normalizeAdaptivePoolConfig(
					*adaptivePoolMinFlag,
					*adaptivePoolMaxFlag,
					*adaptivePoolStreamsPerIdentityFlag,
					effectiveCount,
				)
				adaptiveConfig.Store(config)
				adaptiveEnabled.Store(true)
				log.Printf(
					"TURN identity pool: adaptive for mux v%d (min=%d max=%d streams_per_id=%d)",
					protocolVersion,
					config.minSize,
					config.maxSize,
					config.streamsPerIdentity,
				)
			default:
				adaptiveEnabled.Store(false)
				fixedPoolSize.Store(int32(max(1, effectiveCount)))
				log.Printf("TURN identity pool: fixed size %d", max(1, effectiveCount))
			}
		}

		return poolCredsDynamic(baseGetCreds, targetPoolSize), setStrategy
	}
	if idx := strings.IndexAny(link, "/?#"); idx != -1 {
		link = link[:idx]
	}
	link = normalizeJoinLink(link)
	params := &turnParams{
		host:     *host,
		port:     *port,
		link:     link,
		udp:      *udp,
		getCreds: nil,
		resolver: peerResolver,
	}
	sessionID := []byte(nil)

	if requestedTransport == sessionproto.TransportMode_TRANSPORT_MODE_TCP {
		if *direct {
			log.Panicf("TCP transport does not support -no-dtls")
		}
		if requestedSessionMode == sessionproto.ModeMux {
			log.Panicf("transport=tcp is not supported with session-mode=mux")
		}
		params.getCreds = buildGetCreds(sessionproto.ModeMainline, muxProtocolNone, 1)
		log.Printf("Transport mode: tcp")
		runTCPMode(ctx, params, peer, *listen, *n)
		return
	}

	listenConn, err := net.ListenPacket("udp", *listen) // nolint: noctx
	if err != nil {
		log.Panicf("Failed to listen: %s", err)
	}
	context.AfterFunc(ctx, func() {
		if closeErr := listenConn.Close(); closeErr != nil {
			log.Panicf("Failed to close local connection: %s", closeErr)
		}
	})

	wg1 := sync.WaitGroup{}
	t := time.Tick(200 * time.Millisecond)
	if *direct {
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
		params.getCreds = poolCreds(baseGetCreds, configuredPoolSize)
		for i := 0; i < *n; i++ {
			streamID := i
			wg1.Go(func() {
				oneTurnConnectionLoop(ctx, params, peer, listenConnChan, t, streamID, false)
			})
		}
	} else {
		inboundChan := make(chan *UDPPacket, 2000)
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
		probeMuxCompatibility := func(control *mainlineControlHandle, candidateVersion uint32) bool {
			probeSessionID := resolveSessionID(sessionproto.ModeMux, *sessionIDFlag)
			log.Printf(
				"Compatibility probe: testing mux v%d session hello, session ID: %s",
				candidateVersion,
				hex.EncodeToString(probeSessionID),
			)
			hello, err := buildSessionHelloForVersion(candidateVersion, probeSessionID, 0)
			if err != nil {
				log.Printf("Compatibility probe: failed to build mux v%d session hello: %s", candidateVersion, err)
				return false
			}
			serverHello, err := exchangeMuxSessionHelloOnActiveMainline(control, hello, candidateVersion)
			if err == nil && serverHello.GetMuxSupported() {
				log.Printf("Compatibility probe: mux v%d session hello acknowledged", candidateVersion)
				return true
			}
			if err != nil {
				log.Printf("Compatibility probe: mux v%d session hello was not acknowledged: %s", candidateVersion, err)
				return false
			}
			if serverHello.GetError() != "" {
				log.Printf("Compatibility probe: mux v%d rejected by server: %s", candidateVersion, serverHello.GetError())
			} else {
				log.Printf("Compatibility probe: mux v%d session hello was not acknowledged", candidateVersion)
			}
			return false
		}

		runtimeCtx, runtimeCancel := context.WithCancel(ctx)
		defer func() {
			runtimeCancel()
		}()
		runtimeWG := (*sync.WaitGroup)(nil)

		switch requestedSessionMode {
		case sessionproto.ModeMainline:
			params.getCreds = buildGetCreds(sessionproto.ModeMainline, muxProtocolNone, 1)
			effectiveCount := effectiveStreamCount(sessionproto.ModeMainline, muxProtocolNone)
			logLegacyMuxCompatibility(muxProtocolNone, effectiveCount)
			okchan := make(chan struct{}, 1)
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
				muxProtocolNone,
				okchan,
				nil,
				nil,
				false,
			)
		case sessionproto.ModeMux:
			upgraded := false
			for _, candidateVersion := range []uint32{muxProtocolV3, muxProtocolV2, muxProtocolV1} {
				effectiveCount := effectiveStreamCount(sessionproto.ModeMux, candidateVersion)
				logLegacyMuxCompatibility(candidateVersion, effectiveCount)
				sessionID = resolveSessionID(sessionproto.ModeMux, *sessionIDFlag)
				params.getCreds = buildGetCreds(sessionproto.ModeMux, candidateVersion, effectiveCount)
				log.Printf("Session mode: mux v%d, session ID: %s", candidateVersion, hex.EncodeToString(sessionID))

				okchan := make(chan struct{})
				runtimeWG = startDtlsTurnWorkers(
					runtimeCtx,
					peer,
					listenConn,
					inboundChan,
					params,
					t,
					effectiveCount,
					sessionproto.ModeMux,
					sessionID,
					candidateVersion,
					okchan,
					nil,
					nil,
					false,
				)
				if waitForReady(ctx, okchan, muxReadyTimeout) {
					upgraded = true
					break
				}

				log.Printf("Session mode: mux v%d failed, retrying fallback", candidateVersion)
				runtimeCancel()
				runtimeWG.Wait()
				runtimeCtx, runtimeCancel = context.WithCancel(ctx)
			}

			if !upgraded {
				log.Printf("Session mode: mux fallback -> mainline")
				params.getCreds = buildGetCreds(sessionproto.ModeMainline, muxProtocolNone, 1)
				effectiveCount := effectiveStreamCount(sessionproto.ModeMainline, muxProtocolNone)
				logLegacyMuxCompatibility(muxProtocolNone, effectiveCount)
				okchan := make(chan struct{}, 1)
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
					muxProtocolNone,
					okchan,
					nil,
					nil,
					false,
				)
			}
		case sessionproto.ModeAuto:
			okchan := make(chan struct{})
			probeResult := make(chan uint32, 1)
			mainlineControl := make(chan *mainlineControlHandle, 1)
			autoGetCreds, setAutoPoolStrategy := buildAutoGetCreds()
			setAutoPoolStrategy(sessionproto.ModeMainline, muxProtocolNone, 1)
			params.getCreds = autoGetCreds
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
				muxProtocolNone,
				okchan,
				probeResult,
				mainlineControl,
				true,
			)
			if !waitForReady(ctx, okchan, mainlineBootstrapTimeout) {
				runtimeCancel()
				runtimeWG.Wait()
				log.Fatalf("failed to bootstrap mainline session")
			}

			supportedVersion := waitForProbeVersion(ctx, probeResult, muxProbeTimeout)
			activeMainlineControl := waitForMainlineControlHandle(ctx, mainlineControl, muxProbeTimeout)
			candidateVersions := make([]uint32, 0, 3)
			switch supportedVersion {
			case muxProtocolV3:
				candidateVersions = append(candidateVersions, muxProtocolV3, muxProtocolV2, muxProtocolV1)
			case muxProtocolV2:
				candidateVersions = append(candidateVersions, muxProtocolV2, muxProtocolV1)
			case muxProtocolV1:
				candidateVersions = append(candidateVersions, muxProtocolV1)
			}

			selectedMuxVersion := uint32(0)
			for _, candidateVersion := range candidateVersions {
				if probeMuxCompatibility(activeMainlineControl, candidateVersion) {
					selectedMuxVersion = candidateVersion
					break
				}
			}

			runtimeCancel()
			runtimeWG.Wait()

			if selectedMuxVersion == 0 {
				log.Printf("Session mode: staying on mainline")

				runtimeCtx, runtimeCancel = context.WithCancel(ctx)
				setAutoPoolStrategy(sessionproto.ModeMainline, muxProtocolNone, 1)
				params.getCreds = autoGetCreds
				effectiveCount := effectiveStreamCount(sessionproto.ModeMainline, muxProtocolNone)
				logLegacyMuxCompatibility(muxProtocolNone, effectiveCount)
				okchan := make(chan struct{}, 1)
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
					muxProtocolNone,
					okchan,
					nil,
					nil,
					false,
				)
			} else {
				effectiveCount := effectiveStreamCount(sessionproto.ModeMux, selectedMuxVersion)
				logLegacyMuxCompatibility(selectedMuxVersion, effectiveCount)
				sessionID = resolveSessionID(sessionproto.ModeMux, *sessionIDFlag)
				setAutoPoolStrategy(sessionproto.ModeMux, selectedMuxVersion, effectiveCount)
				params.getCreds = autoGetCreds
				log.Printf("Session mode: mainline -> mux v%d, session ID: %s", selectedMuxVersion, hex.EncodeToString(sessionID))

				runtimeCtx, runtimeCancel = context.WithCancel(ctx)
				okchan = make(chan struct{})
				runtimeWG = startDtlsTurnWorkers(
					runtimeCtx,
					peer,
					listenConn,
					inboundChan,
					params,
					t,
					effectiveCount,
					sessionproto.ModeMux,
					sessionID,
					selectedMuxVersion,
					okchan,
					nil,
					nil,
					false,
				)
				if !waitForReady(ctx, okchan, muxReadyTimeout) {
					log.Printf("Session mode: mux v%d failed after successful compatibility probe, staying on mainline", selectedMuxVersion)
					runtimeCancel()
					runtimeWG.Wait()

					runtimeCtx, runtimeCancel = context.WithCancel(ctx)
					setAutoPoolStrategy(sessionproto.ModeMainline, muxProtocolNone, 1)
					params.getCreds = autoGetCreds
					effectiveCount = effectiveStreamCount(sessionproto.ModeMainline, muxProtocolNone)
					logLegacyMuxCompatibility(muxProtocolNone, effectiveCount)
					okchan = make(chan struct{}, 1)
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
						muxProtocolNone,
						okchan,
						nil,
						nil,
						false,
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
