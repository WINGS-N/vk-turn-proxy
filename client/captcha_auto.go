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
	"math/rand"
	neturl "net/url"
	"regexp"
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

	powInput, difficulty, err := fetchPowInput(ctx, captchaErr.RedirectURI, client, profile)
	if err != nil {
		return "", fmt.Errorf("failed to fetch PoW input: %w", err)
	}

	hash := solvePoW(powInput, difficulty)
	if hash == "" {
		return "", fmt.Errorf("failed to solve PoW")
	}

	successToken, err := callCaptchaNotRobot(ctx, captchaErr.SessionToken, hash, client, profile)
	if err != nil {
		return "", fmt.Errorf("captchaNotRobot API failed: %w", err)
	}

	log.Printf("VK Smart Captcha solved automatically")
	return successToken, nil
}

func fetchPowInput(ctx context.Context, redirectURI string, client tlsclient.HttpClient, profile Profile) (string, int, error) {
	req, err := newFHTTPRequest(ctx, "GET", redirectURI, nil)
	if err != nil {
		return "", 0, err
	}
	applyBrowserProfileFhttp(req, profile)
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	resp, err := client.Do(req)
	if err != nil {
		return "", 0, err
	}
	defer func() {
		if closeErr := resp.Body.Close(); closeErr != nil {
			log.Printf("close captcha html body: %s", closeErr)
		}
	}()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", 0, err
	}
	html := string(body)

	powInputRe := regexp.MustCompile(`const\s+powInput\s*=\s*"([^"]+)"`)
	powInputMatch := powInputRe.FindStringSubmatch(html)
	if len(powInputMatch) < 2 {
		return "", 0, fmt.Errorf("powInput not found in captcha HTML")
	}

	diffRe := regexp.MustCompile(`startsWith\('0'\.repeat\((\d+)\)\)`)
	diffMatch := diffRe.FindStringSubmatch(html)
	difficulty := 2
	if len(diffMatch) >= 2 {
		if parsedDifficulty, parseErr := strconv.Atoi(diffMatch[1]); parseErr == nil {
			difficulty = parsedDifficulty
		}
	}
	return powInputMatch[1], difficulty, nil
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
		req, err := newFHTTPRequest(ctx, "POST", reqURL, []byte(postData))
		if err != nil {
			return nil, err
		}
		applyBrowserProfileFhttp(req, profile)
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("Origin", "https://vk.ru")
		req.Header.Set("Referer", "https://vk.ru/")
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
	deviceJSON := fmt.Sprintf(
		`{"screenWidth":1920,"screenHeight":1080,"screenAvailWidth":1920,"screenAvailHeight":1040,"innerWidth":1920,"innerHeight":969,"devicePixelRatio":1,"language":"en-US","languages":["en-US"],"webdriver":false,"hardwareConcurrency":8,"deviceMemory":8,"connectionEffectiveType":"4g","notificationsPermission":"default","userAgent":"%s","platform":"Win32"}`,
		profile.UserAgent,
	)
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
	connectionDownlinkSamples := make([]string, 0, 16)
	for i := 0; i < 16; i++ {
		connectionDownlinkSamples = append(connectionDownlinkSamples, fmt.Sprintf("%.1f", 8.5+rand.Float64()*2.0))
	}
	connectionDownlink := "[" + strings.Join(connectionDownlinkSamples, ",") + "]"
	checkData := baseParams + fmt.Sprintf(
		"&accelerometer=%s&gyroscope=%s&motion=%s&cursor=%s&taps=%s&connectionRtt=%s&connectionDownlink=%s&browser_fp=%s&hash=%s&answer=%s&debug_info=%s",
		neturl.QueryEscape("[]"),
		neturl.QueryEscape("[]"),
		neturl.QueryEscape("[]"),
		neturl.QueryEscape(cursorJSON),
		neturl.QueryEscape("[]"),
		neturl.QueryEscape("[]"),
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
		return "", fmt.Errorf("invalid check response: %v", checkResp)
	}
	status, _ := respObj["status"].(string)
	if status != "OK" {
		return "", fmt.Errorf("check status: %s", status)
	}
	successToken, ok := respObj["success_token"].(string)
	if !ok || successToken == "" {
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
