package main

import (
	"context"
	"crypto/md5"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	neturl "net/url"
	"strconv"
	"strings"
	"time"

	tlsclient "github.com/bogdanfinn/tls-client"
)

type vkCaptchaError struct {
	ErrorCode      int
	ErrorMsg       string
	CaptchaSid     string
	RedirectURI    string
	SessionToken   string
	CaptchaTs      string
	CaptchaAttempt string
}

func parseVkCaptchaError(errData map[string]interface{}) *vkCaptchaError {
	codeFloat, _ := errData["error_code"].(float64)
	redirectURI, _ := errData["redirect_uri"].(string)
	errorMsg, _ := errData["error_msg"].(string)

	captchaSid, _ := errData["captcha_sid"].(string)
	if captchaSid == "" {
		if sidNum, ok := errData["captcha_sid"].(float64); ok {
			captchaSid = fmt.Sprintf("%.0f", sidNum)
		}
	}

	var sessionToken string
	if redirectURI != "" {
		if parsed, err := neturl.Parse(redirectURI); err == nil {
			sessionToken = parsed.Query().Get("session_token")
		}
	}

	captchaTs := stringCaptchaField(errData, "captcha_ts")
	captchaAttempt := stringCaptchaField(errData, "captcha_attempt")

	return &vkCaptchaError{
		ErrorCode:      int(codeFloat),
		ErrorMsg:       errorMsg,
		CaptchaSid:     captchaSid,
		RedirectURI:    redirectURI,
		SessionToken:   sessionToken,
		CaptchaTs:      captchaTs,
		CaptchaAttempt: captchaAttempt,
	}
}

func solveVkCaptcha(ctx context.Context, captchaErr *vkCaptchaError, resolver *protectedResolver, profile Profile) (string, error) {
	if captchaErr == nil || captchaErr.SessionToken == "" {
		return "", fmt.Errorf("no session_token in redirect_uri")
	}
	log.Printf("Solving VK Smart Captcha automatically...")
	client, err := resolver.newTLSHTTPClient(profile, 20*time.Second)
	if err != nil {
		return "", fmt.Errorf("failed to initialize tls client: %w", err)
	}
	defer client.CloseIdleConnections()

	bootstrap, err := fetchCaptchaBootstrap(ctx, captchaErr.RedirectURI, client, profile)
	if err != nil {
		return "", fmt.Errorf("failed to fetch captcha bootstrap: %w", err)
	}

	hash := solvePoW(bootstrap.PowInput, bootstrap.Difficulty)
	if hash == "" {
		return "", fmt.Errorf("failed to solve PoW")
	}

	successToken, err := callCaptchaNotRobot(ctx, captchaErr.SessionToken, hash, client, profile)
	if err == nil {
		log.Printf("VK Smart Captcha solved automatically")
		return successToken, nil
	}
	log.Printf("VK Smart Captcha PoW-only check did not complete: %v", err)

	if bootstrap.Settings == nil || len(bootstrap.Settings.SettingsByType) == 0 {
		return "", fmt.Errorf("captchaNotRobot API failed: %w", err)
	}

	if sliderSettings := bootstrap.Settings.SettingsByType[sliderCaptchaType]; sliderSettings == "" {
		return "", fmt.Errorf("captchaNotRobot API failed: %w", err)
	}

	log.Printf("Trying slider captcha PoC fallback after PoW-only check failure")
	successToken, fallbackErr := callCaptchaNotRobotWithSliderPOC(
		ctx,
		captchaErr.SessionToken,
		hash,
		0,
		client,
		profile,
		bootstrap.Settings,
	)
	if fallbackErr != nil {
		return "", fmt.Errorf("captchaNotRobot API failed: %w; slider POC fallback failed: %v", err, fallbackErr)
	}

	log.Printf("VK Smart Captcha solved via slider PoC fallback")
	return successToken, nil
}

func fetchCaptchaBootstrap(
	ctx context.Context,
	redirectURI string,
	client tlsclient.HttpClient,
	profile Profile,
) (*captchaBootstrap, error) {
	parsedURL, err := neturl.Parse(redirectURI)
	if err != nil {
		return nil, err
	}
	domain := parsedURL.Hostname()

	req, err := newFHTTPRequest(ctx, "GET", redirectURI, nil)
	if err != nil {
		return nil, err
	}
	req.Host = domain
	applyBrowserProfileFhttp(req, profile)
	req.Header.Set("Sec-Fetch-Site", "none")
	req.Header.Set("Sec-Fetch-Mode", "navigate")
	req.Header.Set("Sec-Fetch-Dest", "document")
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() {
		if closeErr := resp.Body.Close(); closeErr != nil {
			log.Printf("close captcha html body: %s", closeErr)
		}
	}()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	return parseCaptchaBootstrapHTML(string(body))
}

func solvePoW(powInput string, difficulty int) string {
	target := strings.Repeat("0", difficulty)
	for nonce := 1; nonce <= 10_000_000; nonce++ {
		hash := sha256.Sum256([]byte(powInput + strconv.Itoa(nonce)))
		hexHash := hex.EncodeToString(hash[:])
		if strings.HasPrefix(hexHash, target) {
			return hexHash
		}
	}
	return ""
}

func callCaptchaNotRobot(
	ctx context.Context,
	sessionToken string,
	hash string,
	client tlsclient.HttpClient,
	profile Profile,
) (string, error) {
	vkReq := func(method string, postData string) (map[string]interface{}, error) {
		reqURL := "https://api.vk.ru/method/" + method + "?v=5.131"
		parsedURL, err := neturl.Parse(reqURL)
		if err != nil {
			return nil, fmt.Errorf("parse request URL: %w", err)
		}
		domain := parsedURL.Hostname()

		req, err := newFHTTPRequest(ctx, "POST", reqURL, []byte(postData))
		if err != nil {
			return nil, err
		}
		req.Host = domain
		applyBrowserProfileFhttp(req, profile)
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("Accept", "*/*")
		req.Header.Set("Origin", "https://id.vk.ru")
		req.Header.Set("Referer", "https://id.vk.ru/")
		req.Header.Set("Sec-Fetch-Site", "same-site")
		req.Header.Set("Sec-Fetch-Mode", "cors")
		req.Header.Set("Sec-Fetch-Dest", "empty")
		req.Header.Set("Sec-GPC", "1")
		req.Header.Set("Priority", "u=1, i")
		httpResp, err := client.Do(req)
		if err != nil {
			return nil, err
		}
		defer func() {
			if closeErr := httpResp.Body.Close(); closeErr != nil {
				log.Printf("close captcha api body: %s", closeErr)
			}
		}()

		body, err := io.ReadAll(httpResp.Body)
		if err != nil {
			return nil, err
		}
		var resp map[string]interface{}
		if err := json.Unmarshal(body, &resp); err != nil {
			return nil, err
		}
		return resp, nil
	}

	baseParams := fmt.Sprintf(
		"session_token=%s&domain=vk.com&adFp=&access_token=",
		neturl.QueryEscape(sessionToken),
	)

	if _, err := vkReq("captchaNotRobot.settings", baseParams); err != nil {
		return "", fmt.Errorf("settings failed: %w", err)
	}
	time.Sleep(200 * time.Millisecond)

	browserFp := generateBrowserFp(profile)
	deviceJSON := buildCaptchaDeviceJSON(profile)
	componentDoneData := baseParams + fmt.Sprintf(
		"&browser_fp=%s&device=%s",
		browserFp,
		neturl.QueryEscape(deviceJSON),
	)

	if _, err := vkReq("captchaNotRobot.componentDone", componentDoneData); err != nil {
		return "", fmt.Errorf("componentDone failed: %w", err)
	}
	time.Sleep(200 * time.Millisecond)

	cursorJSON := generateFakeCursor()
	answer := base64.StdEncoding.EncodeToString([]byte("{}"))
	debugInfoBytes := md5.Sum([]byte(profile.UserAgent + strconv.FormatInt(time.Now().UnixNano(), 10)))
	debugInfo := hex.EncodeToString(debugInfoBytes[:])
	connectionRtt := "[50,50,50,50,50,50,50,50,50,50]"
	connectionDownlink := "[9.5,9.5,9.5,9.5,9.5,9.5,9.5,9.5,9.5,9.5,9.5,9.5,9.5,9.5,9.5,9.5]"
	checkData := baseParams + fmt.Sprintf(
		"&accelerometer=%s&gyroscope=%s&motion=%s&cursor=%s&taps=%s&connectionRtt=%s&connectionDownlink=%s&browser_fp=%s&hash=%s&answer=%s&debug_info=%s",
		neturl.QueryEscape("[]"),
		neturl.QueryEscape("[]"),
		neturl.QueryEscape("[]"),
		neturl.QueryEscape(cursorJSON),
		neturl.QueryEscape("[]"),
		neturl.QueryEscape(connectionRtt),
		neturl.QueryEscape(connectionDownlink),
		browserFp,
		hash,
		answer,
		debugInfo,
	)

	checkResp, err := vkReq("captchaNotRobot.check", checkData)
	if err != nil {
		return "", fmt.Errorf("check failed: %w", err)
	}
	respObj, ok := checkResp["response"].(map[string]interface{})
	if !ok {
		log.Printf("captchaNotRobot.check returned invalid response: %s", compactCaptchaJSON(checkResp))
		return "", fmt.Errorf("invalid check response: %v", checkResp)
	}
	status, _ := respObj["status"].(string)
	if status != "OK" {
		log.Printf(
			"captchaNotRobot.check non-OK response: status=%q response=%s",
			status,
			compactCaptchaJSON(respObj),
		)
		return "", fmt.Errorf("check status: %s", status)
	}
	successToken, ok := respObj["success_token"].(string)
	if !ok || successToken == "" {
		log.Printf("captchaNotRobot.check missing success_token: %s", compactCaptchaJSON(respObj))
		return "", fmt.Errorf("success_token not found")
	}

	time.Sleep(200 * time.Millisecond)
	_, _ = vkReq("captchaNotRobot.endSession", baseParams)
	return successToken, nil
}

func stringCaptchaField(errData map[string]interface{}, key string) string {
	if value, ok := errData[key].(string); ok {
		return value
	}
	if value, ok := errData[key].(float64); ok {
		return fmt.Sprintf("%.0f", value)
	}
	return ""
}

func compactCaptchaJSON(value interface{}) string {
	data, err := json.Marshal(value)
	if err != nil {
		return fmt.Sprintf("%v", value)
	}
	const maxLen = 512
	if len(data) <= maxLen {
		return string(data)
	}
	return string(data[:maxLen]) + "...(truncated)"
}
