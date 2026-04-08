package main

import (
	"compress/gzip"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	neturl "net/url"
	"os/exec"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	captchaSolvePath    = "/_wingsv/captcha-solve"
	captchaResultPath   = "/_wingsv/captcha-result"
	captchaCancelPath   = "/_wingsv/captcha-cancel"
	captchaCompletePath = "/_wingsv/captcha-complete"
	captchaGenericPath  = "/_wingsv/generic-proxy"
)

var absoluteHTMLURLPattern = regexp.MustCompile(`(?i)\b(src|href|action)=("([^"]+)"|'([^']+)')`)
var captchaPendingState atomic.Int32
var deferredCaptchaPromptState atomic.Int32

const deferredCaptchaWaitTimeout = 5 * time.Minute

var errCaptchaDeferredAlreadyPending = errors.New("deferred captcha already pending")

type captchaBrowserMode struct {
	eventPrefix        string
	source             string
	userAgent          string
	autoOpenBrowser    bool
	markCaptchaPending bool
	waitTimeout        time.Duration
}

type captchaOutcome struct {
	value     string
	cancelled bool
}

func setCaptchaPending(pending bool) {
	if pending {
		captchaPendingState.Store(1)
	} else {
		captchaPendingState.Store(0)
	}
}

func isCaptchaPending() bool {
	return captchaPendingState.Load() != 0
}

func beginDeferredCaptchaPrompt() bool {
	return deferredCaptchaPromptState.CompareAndSwap(0, 1)
}

func endDeferredCaptchaPrompt() {
	deferredCaptchaPromptState.Store(0)
}

func solveCaptchaViaHTTP(captchaImg string, resolver *protectedResolver, userAgent string) (string, error) {
	return runCaptchaBrowserServer(
		resolver,
		nil,
		func(baseURL string) string {
			imageURL := localProxyURL(baseURL, captchaImg)
			return renderCaptchaTemplate("captcha_form", captchaFormPageData{
				PageTitle:    "VK captcha",
				Headline:     "Выполните Captcha действие",
				Summary:      "VK запросил подтверждение",
				ImageURL:     imageURL,
				SolvePath:    captchaSolvePath,
				CompletePath: captchaCompletePath,
				CancelPath:   captchaCancelPath,
			})
		},
		captchaBrowserMode{
			eventPrefix:        "CAPTCHA_REQUIRED: ",
			source:             "primary",
			userAgent:          userAgent,
			autoOpenBrowser:    true,
			markCaptchaPending: true,
		},
	)
}

func solveCaptchaViaHTTPDeferred(captchaImg string, resolver *protectedResolver, userAgent string) (string, error) {
	return runCaptchaBrowserServer(
		resolver,
		nil,
		func(baseURL string) string {
			imageURL := localProxyURL(baseURL, captchaImg)
			return renderCaptchaTemplate("captcha_form", captchaFormPageData{
				PageTitle:    "VK captcha",
				Headline:     "Выполните Captcha действие",
				Summary:      "VK запросил подтверждение для фонового обновления соединений",
				ImageURL:     imageURL,
				SolvePath:    captchaSolvePath,
				CompletePath: captchaCompletePath,
				CancelPath:   captchaCancelPath,
			})
		},
		captchaBrowserMode{
			eventPrefix:     "CAPTCHA_PENDING: ",
			source:          "pool",
			userAgent:       userAgent,
			autoOpenBrowser: false,
			waitTimeout:     deferredCaptchaWaitTimeout,
		},
	)
}

func solveCaptchaViaProxy(redirectURI string, resolver *protectedResolver, userAgent string) (string, error) {
	targetURL, err := neturl.Parse(redirectURI)
	if err != nil {
		return "", fmt.Errorf("invalid redirect URI: %w", err)
	}
	return runCaptchaBrowserServer(
		resolver,
		targetURL,
		nil,
		captchaBrowserMode{
			eventPrefix:        "CAPTCHA_REQUIRED: ",
			source:             "primary",
			userAgent:          userAgent,
			autoOpenBrowser:    true,
			markCaptchaPending: true,
		},
	)
}

func solveCaptchaViaProxyDeferred(redirectURI string, resolver *protectedResolver, userAgent string) (string, error) {
	targetURL, err := neturl.Parse(redirectURI)
	if err != nil {
		return "", fmt.Errorf("invalid redirect URI: %w", err)
	}
	return runCaptchaBrowserServer(
		resolver,
		targetURL,
		nil,
		captchaBrowserMode{
			eventPrefix:     "CAPTCHA_PENDING: ",
			source:          "pool",
			userAgent:       userAgent,
			autoOpenBrowser: false,
			waitTimeout:     deferredCaptchaWaitTimeout,
		},
	)
}

func runCaptchaBrowserServer(
	resolver *protectedResolver,
	targetURL *neturl.URL,
	staticPage func(baseURL string) string,
	mode captchaBrowserMode,
) (string, error) {
	resultCh := make(chan captchaOutcome, 1)
	completeHTML := captchaCompletionHTML()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", fmt.Errorf("listen captcha server: %w", err)
	}
	defer func() {
		if closeErr := listener.Close(); closeErr != nil {
			log.Printf("close captcha listener: %s", closeErr)
		}
	}()

	port := listener.Addr().(*net.TCPAddr).Port
	baseURL := fmt.Sprintf("http://127.0.0.1:%d", port)
	if strings.HasPrefix(mode.eventPrefix, "CAPTCHA_PENDING") && !beginDeferredCaptchaPrompt() {
		_ = listener.Close()
		return "", errCaptchaDeferredAlreadyPending
	}
	if strings.HasPrefix(mode.eventPrefix, "CAPTCHA_PENDING") {
		defer endDeferredCaptchaPrompt()
	}

	sendOutcome := func(outcome captchaOutcome) {
		select {
		case resultCh <- outcome:
		default:
		}
	}

	mux := http.NewServeMux()
	mux.HandleFunc(captchaSolvePath, func(w http.ResponseWriter, r *http.Request) {
		log.Printf("captcha solve request: method=%s uri=%s host=%s", r.Method, r.RequestURI, r.Host)
		if err := r.ParseForm(); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		sendOutcome(captchaOutcome{value: strings.TrimSpace(r.FormValue("key"))})
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = w.Write([]byte("ok"))
	})
	mux.HandleFunc(captchaResultPath, func(w http.ResponseWriter, r *http.Request) {
		log.Printf("captcha result request: method=%s uri=%s host=%s", r.Method, r.RequestURI, r.Host)
		if err := r.ParseForm(); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		sendOutcome(captchaOutcome{value: strings.TrimSpace(r.FormValue("token"))})
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = w.Write([]byte("ok"))
	})
	mux.HandleFunc(captchaCancelPath, func(w http.ResponseWriter, r *http.Request) {
		log.Printf("captcha cancel request: method=%s uri=%s host=%s", r.Method, r.RequestURI, r.Host)
		sendOutcome(captchaOutcome{cancelled: true})
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = w.Write([]byte("cancelled"))
	})
	mux.HandleFunc(captchaCompletePath, func(w http.ResponseWriter, r *http.Request) {
		log.Printf("captcha complete request: method=%s uri=%s host=%s", r.Method, r.RequestURI, r.Host)
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(completeHTML))
	})
	mux.HandleFunc(captchaGenericPath, func(w http.ResponseWriter, r *http.Request) {
		log.Printf("captcha generic request: method=%s uri=%s host=%s rawQuery=%s", r.Method, r.RequestURI, r.Host, r.URL.RawQuery)
		target := strings.TrimSpace(r.URL.Query().Get("proxy_url"))
		if target == "" {
			log.Printf("captcha generic request missing proxy_url")
			http.Error(w, "missing proxy_url", http.StatusBadRequest)
			return
		}
		targetParsed, parseErr := neturl.Parse(target)
		if parseErr != nil || targetParsed.Host == "" {
			log.Printf("captcha generic request invalid proxy_url=%q parseErr=%v", target, parseErr)
			http.Error(w, "invalid proxy_url", http.StatusBadRequest)
			return
		}
		log.Printf("captcha generic proxy target=%s", targetParsed.String())
		newCaptchaGenericReverseProxy(resolver, baseURL, targetParsed, mode.userAgent).ServeHTTP(w, r)
	})

	if targetURL != nil {
		mux.Handle("/", newCaptchaReverseProxy(resolver, targetURL, baseURL, true, mode.userAgent))
	} else {
		mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			log.Printf("captcha root request: method=%s uri=%s host=%s", r.Method, r.RequestURI, r.Host)
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			_, _ = w.Write([]byte(staticPage(baseURL)))
		})
	}

	server := &http.Server{
		Handler:  mux,
		ErrorLog: log.Default(),
	}

	var serveWG sync.WaitGroup
	serveWG.Add(1)
	go func() {
		defer serveWG.Done()
		if serveErr := server.Serve(listener); serveErr != nil && serveErr != http.ErrServerClosed {
			log.Printf("captcha HTTP server error: %s", serveErr)
		}
	}()

	captchaURL := baseURL + "/"
	if mode.markCaptchaPending {
		setCaptchaPending(true)
		defer setCaptchaPending(false)
	}
	eventPrefix := mode.eventPrefix
	if eventPrefix == "" {
		eventPrefix = "CAPTCHA_REQUIRED: "
	}
	source := strings.TrimSpace(mode.source)
	if source == "" {
		source = "primary"
	}
	eventLine := eventPrefix + "source=" + source + " url=" + captchaURL
	if strings.TrimSpace(mode.userAgent) != "" {
		eventLine += " ua_b64=" + base64.RawURLEncoding.EncodeToString([]byte(mode.userAgent))
	}
	fmt.Println(eventLine)
	if mode.autoOpenBrowser {
		openBrowser(captchaURL)
	}

	var outcome captchaOutcome
	if mode.waitTimeout > 0 {
		select {
		case outcome = <-resultCh:
		case <-time.After(mode.waitTimeout):
			fmt.Println("CAPTCHA_EXPIRED")
			shutdownCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			_ = server.Shutdown(shutdownCtx)
			serveWG.Wait()
			return "", fmt.Errorf("captcha wait timeout")
		}
	} else {
		outcome = <-resultCh
	}
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_ = server.Shutdown(shutdownCtx)
	serveWG.Wait()

	if outcome.cancelled {
		fmt.Println("CAPTCHA_CANCELLED")
		return "", fmt.Errorf("captcha cancelled")
	}
	if strings.TrimSpace(outcome.value) == "" {
		return "", fmt.Errorf("captcha returned empty result")
	}
	fmt.Println("CAPTCHA_SOLVED")
	return outcome.value, nil
}

func newCaptchaGenericReverseProxy(
	resolver *protectedResolver,
	baseURL string,
	targetURL *neturl.URL,
	userAgent string,
) *httputil.ReverseProxy {
	return &httputil.ReverseProxy{
		Transport: resolver.newHTTPTransport(),
		Director: func(req *http.Request) {
			req.URL.Scheme = targetURL.Scheme
			req.URL.Host = targetURL.Host
			req.URL.Path = targetURL.Path
			req.URL.RawPath = targetURL.RawPath
			req.URL.RawQuery = targetURL.RawQuery
			req.Host = targetURL.Host
			if strings.TrimSpace(userAgent) != "" {
				req.Header.Set("User-Agent", userAgent)
			}
		},
		ModifyResponse: func(res *http.Response) error {
			if res.StatusCode >= http.StatusBadRequest {
				log.Printf("captcha generic upstream returned %d for %s", res.StatusCode, targetURL.String())
				if shouldServeCaptchaErrorPage(res.Request) {
					return replaceCaptchaErrorResponse(
						res,
						baseURL,
						targetURL,
						classifyCaptchaHTTPFailure(targetURL, res.StatusCode),
					)
				}
			}
			return nil
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			log.Printf("captcha generic proxy error: %s", err)
			writeCaptchaProxyError(w, r, baseURL, targetURL, err, http.StatusBadGateway)
		},
	}
}

func newCaptchaReverseProxy(
	resolver *protectedResolver,
	targetURL *neturl.URL,
	baseURL string,
	injectHTML bool,
	userAgent string,
) *httputil.ReverseProxy {
	return &httputil.ReverseProxy{
		Transport: resolver.newHTTPTransport(),
		Director: func(req *http.Request) {
			req.URL.Scheme = targetURL.Scheme
			req.URL.Host = targetURL.Host
			if req.URL.Path == "/" || req.URL.Path == "" {
				req.URL.Path = targetURL.Path
				req.URL.RawQuery = targetURL.RawQuery
			}
			req.Host = targetURL.Host
			if strings.TrimSpace(userAgent) != "" {
				req.Header.Set("User-Agent", userAgent)
			}
		},
		ModifyResponse: func(res *http.Response) error {
			if res.StatusCode >= http.StatusBadRequest {
				log.Printf("captcha upstream returned %d for %s", res.StatusCode, targetURL.String())
				if shouldServeCaptchaErrorPage(res.Request) {
					return replaceCaptchaErrorResponse(
						res,
						baseURL,
						targetURL,
						classifyCaptchaHTTPFailure(targetURL, res.StatusCode),
					)
				}
			}
			rewriteCaptchaRedirectLocation(res, baseURL, targetURL)
			if !injectHTML {
				return nil
			}
			return injectCaptchaHTMLResponse(res, baseURL)
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			log.Printf("captcha reverse proxy error: %s", err)
			writeCaptchaProxyError(w, r, baseURL, targetURL, err, http.StatusBadGateway)
		},
	}
}

type captchaFailureInfo struct {
	Title   string
	Summary string
	Detail  string
}

func writeCaptchaProxyError(
	w http.ResponseWriter,
	r *http.Request,
	baseURL string,
	targetURL *neturl.URL,
	err error,
	statusCode int,
) {
	failure := classifyCaptchaProxyError(targetURL, err)
	if shouldServeCaptchaErrorPage(r) {
		writeCaptchaErrorPage(w, statusCode, captchaErrorHTML(baseURL, targetURL, failure))
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(statusCode)
	_, _ = io.WriteString(w, failure.Title+": "+failure.Detail)
}

func replaceCaptchaErrorResponse(
	res *http.Response,
	baseURL string,
	targetURL *neturl.URL,
	failure captchaFailureInfo,
) error {
	body := captchaErrorHTML(baseURL, targetURL, failure)
	res.Header.Set("Content-Type", "text/html; charset=utf-8")
	res.Header.Set("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0")
	res.Header.Set("Pragma", "no-cache")
	res.Header.Del("Content-Encoding")
	res.Header.Del("Content-Security-Policy")
	res.Header.Del("Content-Security-Policy-Report-Only")
	res.Header.Del("X-Frame-Options")
	res.Body = io.NopCloser(strings.NewReader(body))
	res.ContentLength = int64(len(body))
	res.Header.Set("Content-Length", fmt.Sprintf("%d", len(body)))
	return nil
}

func shouldServeCaptchaErrorPage(r *http.Request) bool {
	if r == nil {
		return true
	}
	accept := strings.ToLower(strings.TrimSpace(r.Header.Get("Accept")))
	if strings.Contains(accept, "text/html") {
		return true
	}
	switch strings.ToLower(strings.TrimSpace(r.Header.Get("Sec-Fetch-Dest"))) {
	case "", "document", "iframe":
		return true
	default:
		return false
	}
}

func writeCaptchaErrorPage(w http.ResponseWriter, statusCode int, body string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0")
	w.Header().Set("Pragma", "no-cache")
	w.WriteHeader(statusCode)
	_, _ = io.WriteString(w, body)
}

func classifyCaptchaProxyError(targetURL *neturl.URL, err error) captchaFailureInfo {
	detail := strings.TrimSpace(errorString(err))
	lower := strings.ToLower(detail)

	var netErr net.Error
	if (errors.As(err, &netErr) && netErr.Timeout()) || errors.Is(err, context.DeadlineExceeded) {
		return captchaFailureInfo{
			Title:   "Истекло время ожидания",
			Summary: "Прокси не дождалось ответа от страницы проверки",
			Detail:  firstNonEmptyString(detail, "Превышено время ожидания при обращении к странице проверки"),
		}
	}
	if strings.Contains(lower, "no such host") || strings.Contains(lower, "dns lookup failed") || strings.Contains(lower, "no addresses resolved") {
		return captchaFailureInfo{
			Title:   "Не удалось резолвнуть адрес",
			Summary: "Прокси не смогло определить IP адрес сервера проверки",
			Detail:  firstNonEmptyString(detail, "DNS запрос к серверу проверки не удался"),
		}
	}
	if strings.Contains(lower, "connection refused") {
		return captchaFailureInfo{
			Title:   "В соединении отказано",
			Summary: "Удалённый сервер проверки отклонил подключение",
			Detail:  firstNonEmptyString(detail, "Удалённый сервер отказал в соединении"),
		}
	}
	if strings.Contains(lower, "connection reset") || strings.Contains(lower, "broken pipe") || strings.Contains(lower, "eof") {
		return captchaFailureInfo{
			Title:   "Соединение оборвалось",
			Summary: "Связь со страницей проверки оборвалась до завершения загрузки",
			Detail:  firstNonEmptyString(detail, "Соединение со страницей проверки разорвалось"),
		}
	}
	if strings.Contains(lower, "tls") || strings.Contains(lower, "x509") || strings.Contains(lower, "certificate") {
		return captchaFailureInfo{
			Title:   "Ошибка TLS",
			Summary: "Не удалось безопасно установить HTTPS соединение со страницей проверки",
			Detail:  firstNonEmptyString(detail, "TLS подключение к странице проверки завершилось ошибкой"),
		}
	}
	if strings.Contains(lower, "network is unreachable") || strings.Contains(lower, "no route to host") {
		return captchaFailureInfo{
			Title:   "Нет маршрута до сервера",
			Summary: "Прокси не смогло дотянуться до сервера проверки напрямую",
			Detail:  firstNonEmptyString(detail, "Прямой путь до сервера проверки сейчас недоступен"),
		}
	}
	return captchaFailureInfo{
		Title:   "Не удалось загрузить страницу проверки",
		Summary: "Прокси не смогло получить содержимое страницы проверки",
		Detail:  firstNonEmptyString(detail, "Произошла неизвестная ошибка при загрузке страницы проверки"),
	}
}

func classifyCaptchaHTTPFailure(targetURL *neturl.URL, statusCode int) captchaFailureInfo {
	switch statusCode {
	case http.StatusUnauthorized, http.StatusForbidden:
		return captchaFailureInfo{
			Title:   "Сервер отклонил запрос",
			Summary: "Страница проверки вернула отказ в доступе",
			Detail:  fmt.Sprintf("Удалённый сервер проверки ответил HTTP %d", statusCode),
		}
	case http.StatusNotFound, http.StatusGone:
		return captchaFailureInfo{
			Title:   "Страница проверки недоступна",
			Summary: "Удалённый ресурс проверки не найден",
			Detail:  fmt.Sprintf("Удалённый сервер проверки ответил HTTP %d", statusCode),
		}
	default:
		if statusCode >= 500 {
			return captchaFailureInfo{
				Title:   "Сервер проверки недоступен",
				Summary: "Удалённый сервер временно не смог обработать запрос",
				Detail:  fmt.Sprintf("Удалённый сервер проверки ответил HTTP %d", statusCode),
			}
		}
		return captchaFailureInfo{
			Title:   "Страница проверки ответила ошибкой",
			Summary: "Удалённая страница проверки вернула неожиданный статус",
			Detail:  fmt.Sprintf("Удалённый сервер проверки ответил HTTP %d", statusCode),
		}
	}
}

func captchaErrorHTML(baseURL string, targetURL *neturl.URL, failure captchaFailureInfo) string {
	targetHost := "unknown"
	if targetURL != nil && targetURL.Host != "" {
		targetHost = targetURL.Host
	}
	return renderCaptchaTemplate("captcha_error", captchaErrorPageData{
		PageTitle:  failure.Title,
		Title:      failure.Title,
		Summary:    failure.Summary,
		TargetHost: targetHost,
		Detail:     failure.Detail,
		CancelPath: captchaCancelPath,
	})
}

func errorString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

func firstNonEmptyString(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}

func injectCaptchaHTMLResponse(res *http.Response, baseURL string) error {
	contentType := strings.ToLower(res.Header.Get("Content-Type"))
	if !strings.Contains(contentType, "text/html") {
		return nil
	}

	reader := res.Body
	if strings.EqualFold(res.Header.Get("Content-Encoding"), "gzip") {
		gzipReader, err := gzip.NewReader(res.Body)
		if err == nil {
			reader = gzipReader
			defer func() {
				if closeErr := gzipReader.Close(); closeErr != nil {
					log.Printf("close captcha gzip reader: %s", closeErr)
				}
			}()
		}
	}

	bodyBytes, err := io.ReadAll(reader)
	if err != nil {
		return err
	}
	if closeErr := res.Body.Close(); closeErr != nil {
		log.Printf("close captcha response body: %s", closeErr)
	}

	html := string(bodyBytes)
	html = rewriteAbsoluteHTMLURLs(html, baseURL)
	html = injectCaptchaEnhancements(html)

	res.Body = io.NopCloser(strings.NewReader(html))
	res.ContentLength = int64(len(html))
	res.Header.Set("Content-Length", fmt.Sprintf("%d", len(html)))
	res.Header.Del("Content-Encoding")
	res.Header.Del("Content-Security-Policy")
	res.Header.Del("Content-Security-Policy-Report-Only")
	res.Header.Del("X-Frame-Options")
	return nil
}

func injectCaptchaEnhancements(html string) string {
	styleAndScript := captchaInjectedEnhancements()
	if strings.Contains(strings.ToLower(html), "</head>") {
		return strings.Replace(html, "</head>", styleAndScript+"</head>", 1)
	}
	if strings.Contains(strings.ToLower(html), "</body>") {
		return strings.Replace(html, "</body>", styleAndScript+"</body>", 1)
	}
	return html + styleAndScript
}

func rewriteAbsoluteHTMLURLs(html string, baseURL string) string {
	return absoluteHTMLURLPattern.ReplaceAllStringFunc(html, func(match string) string {
		parts := absoluteHTMLURLPattern.FindStringSubmatch(match)
		if len(parts) < 5 {
			return match
		}
		attrName := parts[1]
		quotedValue := parts[2]
		rawValue := parts[3]
		if rawValue == "" {
			rawValue = parts[4]
		}
		if rawValue == "" {
			return match
		}
		lowerValue := strings.ToLower(rawValue)
		if !strings.HasPrefix(lowerValue, "http://") && !strings.HasPrefix(lowerValue, "https://") {
			return match
		}
		rewritten := localProxyURL(baseURL, rawValue)
		quote := `"`
		if strings.HasPrefix(quotedValue, "'") {
			quote = `'`
		}
		return attrName + "=" + quote + rewritten + quote
	})
}

func rewriteCaptchaRedirectLocation(res *http.Response, baseURL string, targetURL *neturl.URL) {
	location := strings.TrimSpace(res.Header.Get("Location"))
	if location == "" {
		return
	}
	if strings.HasPrefix(location, "/") {
		return
	}
	prefix := targetURL.Scheme + "://" + targetURL.Host
	if strings.HasPrefix(location, prefix) || strings.HasPrefix(location, "http://") || strings.HasPrefix(location, "https://") {
		res.Header.Set("Location", localProxyURL(baseURL, location))
	}
}

func localProxyURL(baseURL string, target string) string {
	return baseURL + captchaGenericPath + "?proxy_url=" + neturl.QueryEscape(target)
}

func captchaInjectedEnhancements() string {
	return renderCaptchaTemplate("captcha_injected_snippet", captchaInjectedSnippetData{
		GenericPath:  captchaGenericPath,
		ResultPath:   captchaResultPath,
		CompletePath: captchaCompletePath,
	})
}

func captchaCompletionHTML() string {
	return renderCaptchaTemplate("captcha_complete", nil)
}

func openBrowser(url string) {
	switch runtime.GOOS {
	case "windows":
		_ = exec.Command("cmd", "/c", "start", url).Start()
	case "darwin":
		_ = exec.Command("open", url).Start()
	case "linux":
		_ = exec.Command("xdg-open", url).Start()
	case "android":
		// Android client is expected to handle CAPTCHA_REQUIRED via the host app.
	}
}
