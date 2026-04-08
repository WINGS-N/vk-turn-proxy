package main

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net/http"
	neturl "net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
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

	powInput, difficulty, err := fetchPowInput(ctx, captchaErr.RedirectURI, resolver, profile)
	if err != nil {
		return "", fmt.Errorf("failed to fetch PoW input: %w", err)
	}

	hash := solvePoW(powInput, difficulty)
	if hash == "" {
		return "", fmt.Errorf("failed to solve PoW")
	}

	successToken, err := callCaptchaNotRobot(ctx, captchaErr.SessionToken, hash, resolver, profile)
	if err != nil {
		return "", fmt.Errorf("captchaNotRobot API failed: %w", err)
	}

	log.Printf("VK Smart Captcha solved automatically")
	return successToken, nil
}

func fetchPowInput(ctx context.Context, redirectURI string, resolver *protectedResolver, profile Profile) (string, int, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", redirectURI, nil)
	if err != nil {
		return "", 0, err
	}
	applyBrowserProfile(req, profile)
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")

	client := resolver.newHTTPClient(20 * time.Second)
	defer client.CloseIdleConnections()
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
	resolver *protectedResolver,
	profile Profile,
) (string, error) {
	vkReq := func(method string, postData string) (map[string]interface{}, error) {
		reqURL := "https://api.vk.ru/method/" + method + "?v=5.131"
		req, err := http.NewRequestWithContext(ctx, "POST", reqURL, strings.NewReader(postData))
		if err != nil {
			return nil, err
		}
		applyBrowserProfile(req, profile)
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("Origin", "https://vk.ru")
		req.Header.Set("Referer", "https://vk.ru/")

		client := resolver.newHTTPClient(20 * time.Second)
		defer client.CloseIdleConnections()
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

	browserFp := fmt.Sprintf("%032x", rand.Int63())
	deviceJSON := `{"screenWidth":1920,"screenHeight":1080,"screenAvailWidth":1920,"screenAvailHeight":1032,"innerWidth":1920,"innerHeight":945,"devicePixelRatio":1,"language":"en-US","languages":["en-US"],"webdriver":false,"hardwareConcurrency":16,"deviceMemory":8,"connectionEffectiveType":"4g","notificationsPermission":"denied"}`
	componentDoneData := baseParams + fmt.Sprintf(
		"&browser_fp=%s&device=%s",
		browserFp,
		neturl.QueryEscape(deviceJSON),
	)

	if _, err := vkReq("captchaNotRobot.componentDone", componentDoneData); err != nil {
		return "", fmt.Errorf("componentDone failed: %w", err)
	}
	time.Sleep(200 * time.Millisecond)

	cursorJSON := `[{"x":950,"y":500},{"x":945,"y":510},{"x":940,"y":520},{"x":938,"y":525},{"x":938,"y":525}]`
	answer := base64.StdEncoding.EncodeToString([]byte("{}"))
	debugInfo := "d44f534ce8deb56ba20be52e05c433309b49ee4d2a70602deeb17a1954257785"
	checkData := baseParams + fmt.Sprintf(
		"&accelerometer=%s&gyroscope=%s&motion=%s&cursor=%s&taps=%s&connectionRtt=%s&connectionDownlink=%s&browser_fp=%s&hash=%s&answer=%s&debug_info=%s",
		neturl.QueryEscape("[]"),
		neturl.QueryEscape("[]"),
		neturl.QueryEscape("[]"),
		neturl.QueryEscape(cursorJSON),
		neturl.QueryEscape("[]"),
		neturl.QueryEscape("[]"),
		neturl.QueryEscape("[9.5,9.5,9.5,9.5,9.5,9.5,9.5,9.5,9.5,9.5,9.5,9.5,9.5,9.5,9.5,9.5]"),
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
