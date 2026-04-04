// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"github.com/cacggghp/vk-turn-proxy/sessionproto"
	"github.com/cbeuw/connutil"
	"github.com/google/uuid"
	"github.com/pion/dtls/v3"
	"github.com/pion/dtls/v3/pkg/crypto/selfsign"
	"github.com/pion/logging"
	"github.com/pion/turn/v5"
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
)

type getCredsFunc func(string) (string, string, string, error)

func getVkCredsWithFallback(link string, resolver *protectedResolver, allowInteractiveFallback bool) (string, string, string, error) {
	profile := getRandomProfile()
	name := generateName()
	escapedName := neturl.QueryEscape(name)

	log.Printf("Connecting identity - Name: %s | User-Agent: %s", name, profile.UserAgent)

	doRequest := func(data string, url string) (resp map[string]interface{}, err error) {
		client := resolver.newHTTPClient(20 * time.Second)
		defer client.CloseIdleConnections()
		req, err := http.NewRequest("POST", url, bytes.NewBuffer([]byte(data)))
		if err != nil {
			return nil, err
		}

		req.Header.Add("User-Agent", profile.UserAgent)
		req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

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

	resp, err := doRequest(data, url)
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

	data = fmt.Sprintf("vk_join_link=https://vk.com/call/join/%s&name=%s&access_token=%s", link, escapedName, token1)
	url = "https://api.vk.ru/method/calls.getAnonymousToken?v=5.274&client_id=6287487"

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
					return "", "", "", fmt.Errorf("captcha failed after %d attempts", maxCaptchaAttempts)
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
					successToken, solveErr := solveVkCaptcha(
						context.Background(),
						captchaErr,
						resolver,
						profile.UserAgent,
					)
					if solveErr == nil {
						usedAutoCaptcha = true
						log.Printf("VK smart captcha produced success token, retrying auth")
					} else if allowInteractiveFallback {
						log.Printf("Auto captcha solve did not complete, opening browser fallback: %s", solveErr)
						successToken, solveErr = solveCaptchaViaProxy(captchaErr.RedirectURI, resolver)
					} else {
						log.Printf("Auto captcha solve needs user confirmation, deferring to app notification")
						successToken, solveErr = solveCaptchaViaProxyDeferred(captchaErr.RedirectURI, resolver)
					}
					if solveErr != nil {
						return "", "", "", fmt.Errorf("smart captcha solve error: %s", solveErr)
					}
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
						captchaKey, solveErr := solveCaptchaViaHTTPDeferred(captchaImg, resolver)
						if solveErr != nil {
							return "", "", "", fmt.Errorf("captcha solve error: %s", solveErr)
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
					captchaKey, solveErr := solveCaptchaViaHTTP(captchaImg, resolver)
					if solveErr != nil {
						return "", "", "", fmt.Errorf("captcha solve error: %s", solveErr)
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

	data = fmt.Sprintf("%s%s%s", "session_data=%7B%22version%22%3A2%2C%22device_id%22%3A%22", uuid.New(), "%22%2C%22client_version%22%3A1.1%2C%22client_type%22%3A%22SDK_JS%22%7D&method=auth.anonymLogin&format=JSON&application_key=CGMMEJLGDIHBABABA")
	url = "https://calls.okcdn.ru/fb.do"

	resp, err = doRequest(data, url)
	if err != nil {
		return "", "", "", fmt.Errorf("request error:%s", err)
	}

	token3 := resp["session_key"].(string)

	data = fmt.Sprintf("joinLink=%s&isVideo=false&protocolVersion=5&anonymToken=%s&method=vchat.joinConversationByLink&format=JSON&application_key=CGMMEJLGDIHBABABA&session_key=%s", link, token2, token3)
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
	userAgent := profile.UserAgent
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
	req.Header.Set("User-Agent", userAgent)
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
	h.Set("User-Agent", userAgent)

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
				UserAgent:      userAgent,
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
	config := &dtls.Config{
		Certificates:          []tls.Certificate{certificate},
		InsecureSkipVerify:    true,
		ExtendedMasterSecret:  dtls.RequireExtendedMasterSecret,
		CipherSuites:          []dtls.CipherSuiteID{dtls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256},
		ConnectionIDGenerator: dtls.OnlySendCIDGenerator(),
	}
	ctx1, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
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
	listenConnChan <-chan net.PacketConn,
	params *turnParams,
	t <-chan time.Time,
	n int,
	sessionMode sessionproto.Mode,
	sessionID []byte,
	protocolVersion uint32,
	firstReady chan<- struct{},
	firstProbeResult chan<- uint32,
) *sync.WaitGroup {
	wg := &sync.WaitGroup{}
	connchan := make(chan net.PacketConn)

	wg.Go(func() {
		oneDtlsConnectionLoop(ctx, peer, listenConnChan, connchan, firstReady, firstProbeResult, sessionMode, sessionID, protocolVersion, 0)
	})
	wg.Go(func() {
		oneTurnConnectionLoop(ctx, params, peer, connchan, t)
	})

	for i := 0; i < n-1; i++ {
		connchan := make(chan net.PacketConn)
		streamID := byte(i + 1)
		wg.Go(func() {
			oneDtlsConnectionLoop(ctx, peer, listenConnChan, connchan, nil, nil, sessionMode, sessionID, protocolVersion, streamID)
		})
		wg.Go(func() {
			oneTurnConnectionLoop(ctx, params, peer, connchan, t)
		})
	}

	return wg
}

func oneDtlsConnection(
	ctx context.Context,
	peer *net.UDPAddr,
	listenConn net.PacketConn,
	connchan chan<- net.PacketConn,
	okchan chan<- struct{},
	probeResult chan<- uint32,
	c chan<- error,
	sessionMode sessionproto.Mode,
	sessionID []byte,
	protocolVersion uint32,
	streamID byte,
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
	if sessionMode == sessionproto.ModeMux {
		hello, err1 := buildSessionHelloForVersion(protocolVersion, sessionID, streamID)
		if err1 != nil {
			err = fmt.Errorf("failed to build session hello: %s", err1)
			return
		}
		serverHello, err1 := exchangeServerHello(dtlsConn, hello)
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
		log.Printf("Established DTLS connection and completed mux negotiation for stream %d!\n", streamID)
	} else {
		log.Printf("Established DTLS connection!\n")
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
	wg.Add(2)
	context.AfterFunc(dtlsctx, func() {
		if err := listenConn.SetDeadline(time.Now()); err != nil {
			log.Printf("Failed to set listener deadline: %s", err)
		}
		if err := dtlsConn.SetDeadline(time.Now()); err != nil {
			log.Printf("Failed to set DTLS deadline: %s", err)
		}
	})
	var addr atomic.Value
	// Start read-loop on listenConn
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
			n, addr1, err1 := listenConn.ReadFrom(buf)
			if err1 != nil {
				log.Printf("Failed: %s", err1)
				return
			}

			addr.Store(addr1) // store peer

			dtlsWriteMu.Lock()
			_, err1 = dtlsConn.Write(buf[:n])
			dtlsWriteMu.Unlock()
			if err1 != nil {
				log.Printf("Failed: %s", err1)
				return
			}
		}
	}()

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
			addr1, ok := addr.Load().(net.Addr)
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
	if sessionMode != sessionproto.ModeMux && probeResult != nil {
		go func() {
			version := probeHighestMuxVersionOnActiveMainline(dtlsConn, dtlsWriteMu, controlResponses)
			select {
			case probeResult <- version:
			default:
			}
		}()
	}

	wg.Wait()
	if err := listenConn.SetDeadline(time.Time{}); err != nil {
		log.Printf("Failed to clear listener deadline: %s", err)
	}
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

func oneTurnConnection(ctx context.Context, turnParams *turnParams, peer *net.UDPAddr, conn2 net.PacketConn, c chan<- error) {
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
	defer func() {
		if err1 := relayConn.Close(); err1 != nil {
			err = fmt.Errorf("failed to close TURN allocated connection: %s", err1)
		}
	}()

	// The relayConn's local address is actually the transport
	// address assigned on the TURN server.
	log.Printf("relayed-address=%s", relayConn.LocalAddr().String())

	wg := sync.WaitGroup{}
	wg.Add(2)
	turnctx, turncancel := context.WithCancel(context.Background())
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
	listenConnChan <-chan net.PacketConn,
	connchan chan<- net.PacketConn,
	okchan chan<- struct{},
	probeResult chan<- uint32,
	sessionMode sessionproto.Mode,
	sessionID []byte,
	protocolVersion uint32,
	streamID byte,
) {
	for {
		select {
		case <-ctx.Done():
			return
		case listenConn := <-listenConnChan:
			c := make(chan error)
			go oneDtlsConnection(ctx, peer, listenConn, connchan, okchan, probeResult, c, sessionMode, sessionID, protocolVersion, streamID)
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
}

func oneTurnConnectionLoop(ctx context.Context, turnParams *turnParams, peer *net.UDPAddr, connchan <-chan net.PacketConn, t <-chan time.Time) {
	for {
		select {
		case <-ctx.Done():
			return
		case conn2 := <-connchan:
			select {
			case <-t:
				c := make(chan error)
				go oneTurnConnection(ctx, turnParams, peer, conn2, c)
				if err := <-c; err != nil {
					log.Printf("%s; reconnecting in %s", err, workerReconnectBackoff)
				} else {
					log.Printf("TURN worker stopped; reconnecting in %s", workerReconnectBackoff)
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
	udp := flag.Bool("udp", false, "connect to TURN with UDP")
	direct := flag.Bool("no-dtls", false, "connect without obfuscation. DO NOT USE")
	protectSock := flag.String("protect-sock", "", "unix socket used for VpnService.protect fd bridge")
	sessionModeFlag := flag.String("session-mode", string(sessionproto.ModeAuto), "TURN session mode: mainline|mux|auto")
	sessionIDFlag := flag.String("session-id", "", "override session ID (hex, 32 chars) for mux mode")
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

	var link string
	var getCreds getCredsFunc
	if *vklink != "" {
		parts := strings.Split(*vklink, "join/")
		link = parts[len(parts)-1]

		if *n <= 0 {
			*n = 10
		}
		getCreds = poolCreds(func(s string, allowInteractiveFallback bool) (string, string, string, error) {
			return getVkCredsWithFallback(s, peerResolver, allowInteractiveFallback)
		}, *n)
	} else {
		parts := strings.Split(*yalink, "j/")
		link = parts[len(parts)-1]
		if *n <= 0 {
			*n = 1
		}
		getCreds = poolCreds(func(s string, _ bool) (string, string, string, error) {
			return getYandexCreds(s, peerResolver)
		}, *n)
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
		getCreds: getCreds,
		resolver: peerResolver,
	}
	sessionID := []byte(nil)

	listenConnChan := make(chan net.PacketConn)
	listenConn, err := net.ListenPacket("udp", *listen) // nolint: noctx
	if err != nil {
		log.Panicf("Failed to listen: %s", err)
	}
	context.AfterFunc(ctx, func() {
		if closeErr := listenConn.Close(); closeErr != nil {
			log.Panicf("Failed to close local connection: %s", closeErr)
		}
	})
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case listenConnChan <- listenConn:
			}
		}
	}()

	wg1 := sync.WaitGroup{}
	t := time.Tick(200 * time.Millisecond)
	if *direct {
		for i := 0; i < *n; i++ {
			wg1.Go(func() {
				oneTurnConnectionLoop(ctx, params, peer, listenConnChan, t)
			})
		}
	} else {
		runtimeCtx, runtimeCancel := context.WithCancel(ctx)
		defer func() {
			runtimeCancel()
		}()
		runtimeWG := (*sync.WaitGroup)(nil)

		switch requestedSessionMode {
		case sessionproto.ModeMainline:
			runtimeWG = startDtlsTurnWorkers(runtimeCtx, peer, listenConnChan, params, t, *n, sessionproto.ModeMainline, nil, muxProtocolNone, nil, nil)
		case sessionproto.ModeMux:
			upgraded := false
			for _, candidateVersion := range []uint32{muxProtocolV2, muxProtocolV1} {
				sessionID = resolveSessionID(sessionproto.ModeMux, *sessionIDFlag)
				log.Printf("Session mode: mux v%d, session ID: %s", candidateVersion, hex.EncodeToString(sessionID))

				okchan := make(chan struct{})
				runtimeWG = startDtlsTurnWorkers(runtimeCtx, peer, listenConnChan, params, t, *n, sessionproto.ModeMux, sessionID, candidateVersion, okchan, nil)
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
				runtimeWG = startDtlsTurnWorkers(runtimeCtx, peer, listenConnChan, params, t, *n, sessionproto.ModeMainline, nil, muxProtocolNone, nil, nil)
			}
		case sessionproto.ModeAuto:
			okchan := make(chan struct{})
			probeResult := make(chan uint32, 1)
			runtimeWG = startDtlsTurnWorkers(runtimeCtx, peer, listenConnChan, params, t, 1, sessionproto.ModeMainline, nil, muxProtocolNone, okchan, probeResult)
			if !waitForReady(ctx, okchan, mainlineBootstrapTimeout) {
				runtimeCancel()
				runtimeWG.Wait()
				log.Fatalf("failed to bootstrap mainline session")
			}

			supportedVersion := waitForProbeVersion(ctx, probeResult, muxProbeTimeout)
			candidateVersions := make([]uint32, 0, 2)
			switch supportedVersion {
			case muxProtocolV2:
				candidateVersions = append(candidateVersions, muxProtocolV2, muxProtocolV1)
			case muxProtocolV1:
				candidateVersions = append(candidateVersions, muxProtocolV1)
			}

			upgraded := false
			for _, candidateVersion := range candidateVersions {
				runtimeCancel()
				runtimeWG.Wait()

				sessionID = resolveSessionID(sessionproto.ModeMux, *sessionIDFlag)
				log.Printf("Session mode: mainline -> mux v%d, session ID: %s", candidateVersion, hex.EncodeToString(sessionID))

				runtimeCtx, runtimeCancel = context.WithCancel(ctx)
				okchan = make(chan struct{})
				runtimeWG = startDtlsTurnWorkers(runtimeCtx, peer, listenConnChan, params, t, *n, sessionproto.ModeMux, sessionID, candidateVersion, okchan, nil)
				if waitForReady(ctx, okchan, muxReadyTimeout) {
					upgraded = true
					break
				}
				log.Printf("Session mode: mux v%d failed, falling back", candidateVersion)
			}

			if !upgraded {
				log.Printf("Session mode: staying on mainline")
				runtimeCancel()
				runtimeWG.Wait()

				runtimeCtx, runtimeCancel = context.WithCancel(ctx)
				runtimeWG = startDtlsTurnWorkers(runtimeCtx, peer, listenConnChan, params, t, *n, sessionproto.ModeMainline, nil, muxProtocolNone, nil, nil)
			}
		}

		wg1.Go(func() {
			runtimeWG.Wait()
		})
	}

	wg1.Wait()
}
