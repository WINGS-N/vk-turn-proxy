package main

import (
	"compress/gzip"
	"context"
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

func solveCaptchaViaHTTP(captchaImg string, resolver *protectedResolver) (string, error) {
	return runCaptchaBrowserServer(
		resolver,
		nil,
		func(baseURL string) string {
			imageURL := localProxyURL(baseURL, captchaImg)
			return fmt.Sprintf(`<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>VK captcha</title>
  %s
</head>
<body>
  <div class="captcha-shell">
    <div class="captcha-card">
      <div class="captcha-eyebrow">VK TURN</div>
      <h1>Выполните Captcha действие</h1>
      <p>Прокси запросило подтверждение от VK</p>
      <img class="captcha-image" src="%s" alt="captcha">
      <form onsubmit="return submitCaptchaKey();">
        <input id="captcha-key" class="captcha-input" type="text" autocomplete="off" autocapitalize="none" spellcheck="false" placeholder="Код с картинки">
        <button class="captcha-primary" type="submit">Подтвердить</button>
      </form>
      <button class="captcha-secondary" type="button" onclick="cancelCaptcha()">Отмена</button>
    </div>
  </div>
  <script>
    function submitCaptchaKey() {
      const value = document.getElementById('captcha-key').value || '';
      fetch('%s?key=' + encodeURIComponent(value), { method: 'POST' })
        .then(function() { window.location = '%s?status=success'; });
      return false;
    }
    function cancelCaptcha() {
      fetch('%s', { method: 'POST' })
        .finally(function() { window.location = '%s?status=cancelled'; });
    }
  </script>
</body>
</html>`,
				captchaSharedStyle(),
				imageURL,
				captchaSolvePath,
				captchaCompletePath,
				captchaCancelPath,
				captchaCompletePath,
			)
		},
		captchaBrowserMode{
			eventPrefix:        "CAPTCHA_REQUIRED: ",
			autoOpenBrowser:    true,
			markCaptchaPending: true,
		},
	)
}

func solveCaptchaViaHTTPDeferred(captchaImg string, resolver *protectedResolver) (string, error) {
	return runCaptchaBrowserServer(
		resolver,
		nil,
		func(baseURL string) string {
			imageURL := localProxyURL(baseURL, captchaImg)
			return fmt.Sprintf(`<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>VK captcha</title>
  %s
</head>
<body>
  <div class="captcha-shell">
    <div class="captcha-card">
      <div class="captcha-eyebrow">VK TURN</div>
      <h1>Выполните Captcha действие</h1>
      <p>Прокси запросило подтверждение от VK для фонового обновления соединений</p>
      <img class="captcha-image" src="%s" alt="captcha">
      <form onsubmit="return submitCaptchaKey();">
        <input id="captcha-key" class="captcha-input" type="text" autocomplete="off" autocapitalize="none" spellcheck="false" placeholder="Код с картинки">
        <button class="captcha-primary" type="submit">Подтвердить</button>
      </form>
      <button class="captcha-secondary" type="button" onclick="cancelCaptcha()">Отмена</button>
    </div>
  </div>
  <script>
    function submitCaptchaKey() {
      const value = document.getElementById('captcha-key').value || '';
      fetch('%s?key=' + encodeURIComponent(value), { method: 'POST' })
        .then(function() { window.location = '%s?status=success'; });
      return false;
    }
    function cancelCaptcha() {
      fetch('%s', { method: 'POST' })
        .finally(function() { window.location = '%s?status=cancelled'; });
    }
  </script>
</body>
</html>`,
				captchaSharedStyle(),
				imageURL,
				captchaSolvePath,
				captchaCompletePath,
				captchaCancelPath,
				captchaCompletePath,
			)
		},
		captchaBrowserMode{
			eventPrefix:     "CAPTCHA_PENDING: ",
			autoOpenBrowser: false,
			waitTimeout:     deferredCaptchaWaitTimeout,
		},
	)
}

func solveCaptchaViaProxy(redirectURI string, resolver *protectedResolver) (string, error) {
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
			autoOpenBrowser:    true,
			markCaptchaPending: true,
		},
	)
}

func solveCaptchaViaProxyDeferred(redirectURI string, resolver *protectedResolver) (string, error) {
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
		newCaptchaGenericReverseProxy(resolver, targetParsed).ServeHTTP(w, r)
	})

	if targetURL != nil {
		mux.Handle("/", newCaptchaReverseProxy(resolver, targetURL, baseURL, true))
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
	fmt.Println(eventPrefix + captchaURL)
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
	targetURL *neturl.URL,
) *httputil.ReverseProxy {
	return &httputil.ReverseProxy{
		Transport: resolver.newProtectedSystemHTTPTransport(),
		Director: func(req *http.Request) {
			req.URL.Scheme = targetURL.Scheme
			req.URL.Host = targetURL.Host
			req.URL.Path = targetURL.Path
			req.URL.RawPath = targetURL.RawPath
			req.URL.RawQuery = targetURL.RawQuery
			req.Host = targetURL.Host
		},
		ModifyResponse: func(res *http.Response) error {
			if res.StatusCode >= http.StatusBadRequest {
				log.Printf("captcha generic upstream returned %d for %s", res.StatusCode, targetURL.String())
			}
			return nil
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			log.Printf("captcha generic proxy error: %s", err)
			http.Error(w, "proxy error", http.StatusBadGateway)
		},
	}
}

func newCaptchaReverseProxy(
	resolver *protectedResolver,
	targetURL *neturl.URL,
	baseURL string,
	injectHTML bool,
) *httputil.ReverseProxy {
	return &httputil.ReverseProxy{
		Transport: resolver.newProtectedSystemHTTPTransport(),
		Director: func(req *http.Request) {
			req.URL.Scheme = targetURL.Scheme
			req.URL.Host = targetURL.Host
			if req.URL.Path == "/" || req.URL.Path == "" {
				req.URL.Path = targetURL.Path
				req.URL.RawQuery = targetURL.RawQuery
			}
			req.Host = targetURL.Host
		},
		ModifyResponse: func(res *http.Response) error {
			if res.StatusCode >= http.StatusBadRequest {
				log.Printf("captcha upstream returned %d for %s", res.StatusCode, targetURL.String())
			}
			rewriteCaptchaRedirectLocation(res, baseURL, targetURL)
			if !injectHTML {
				return nil
			}
			return injectCaptchaHTMLResponse(res, baseURL)
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			log.Printf("captcha reverse proxy error: %s", err)
			http.Error(w, "proxy error", http.StatusBadGateway)
		},
	}
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

func captchaSharedStyle() string {
	return `<style>
html, body {
  margin: 0;
  min-height: 100%;
  background: #f5f5f7;
  color: #111111;
  font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
}
.captcha-shell {
  min-height: 100vh;
  display: flex;
  align-items: center;
  justify-content: center;
  padding: 24px;
  box-sizing: border-box;
}
.captcha-card {
  width: 100%;
  max-width: 520px;
  background: #ffffff;
  border-radius: 28px;
  box-shadow: 0 12px 40px rgba(0, 0, 0, 0.12);
  padding: 28px;
  box-sizing: border-box;
}
.captcha-eyebrow {
  display: inline-block;
  border-radius: 999px;
  background: rgba(17, 17, 17, 0.08);
  color: #555555;
  font-size: 12px;
  font-weight: 600;
  letter-spacing: 0.08em;
  text-transform: uppercase;
  padding: 6px 10px;
}
.captcha-card h1 {
  margin: 16px 0 8px;
  font-size: 28px;
  line-height: 1.2;
}
.captcha-card p {
  margin: 0 0 20px;
  color: #666666;
  line-height: 1.5;
}
.captcha-image {
  width: 100%;
  border-radius: 20px;
  background: #f0f0f2;
  display: block;
  margin-bottom: 18px;
}
.captcha-input,
.captcha-primary,
.captcha-secondary {
  width: 100%;
  box-sizing: border-box;
  border-radius: 18px;
  font-size: 16px;
}
.captcha-input {
  border: 1px solid rgba(17, 17, 17, 0.12);
  padding: 15px 16px;
  margin-bottom: 14px;
  background: #ffffff;
}
.captcha-primary,
.captcha-secondary {
  border: none;
  padding: 15px 16px;
  font-weight: 600;
}
.captcha-primary {
  background: #0d6efd;
  color: #ffffff;
}
.captcha-secondary {
  background: rgba(17, 17, 17, 0.08);
  color: #111111;
  margin-top: 10px;
}
a, button {
  -webkit-tap-highlight-color: transparent;
}
</style>`
}

func captchaInjectedEnhancements() string {
	return captchaSharedStyle() + `<script>
(function() {
  function rewriteUrl(urlStr) {
    if (!urlStr || typeof urlStr !== 'string') return urlStr;
    if (urlStr.indexOf('http://') === 0 || urlStr.indexOf('https://') === 0) {
      return '` + captchaGenericPath + `?proxy_url=' + encodeURIComponent(urlStr);
    }
    return urlStr;
  }

  var origOpen = XMLHttpRequest.prototype.open;
  var origSend = XMLHttpRequest.prototype.send;
  XMLHttpRequest.prototype.open = function() {
    if (arguments[1] && typeof arguments[1] === 'string') {
      this._origUrl = arguments[1];
      arguments[1] = rewriteUrl(arguments[1]);
    }
    return origOpen.apply(this, arguments);
  };
  XMLHttpRequest.prototype.send = function() {
    var xhr = this;
    if (this._origUrl && this._origUrl.indexOf('captchaNotRobot.check') !== -1) {
      xhr.addEventListener('load', function() {
        try {
          var data = JSON.parse(xhr.responseText);
          if (data.response && data.response.success_token) {
            fetch('` + captchaResultPath + `', {
              method: 'POST',
              headers: {'Content-Type': 'application/x-www-form-urlencoded'},
              body: 'token=' + encodeURIComponent(data.response.success_token)
            }).then(function() {
              window.location = '` + captchaCompletePath + `?status=success';
            });
          }
        } catch (e) {}
      });
    }
    return origSend.apply(this, arguments);
  };

  var origFetch = window.fetch;
  if (origFetch) {
    window.fetch = function() {
      var url = arguments[0];
      var isObj = (typeof url === 'object' && url && url.url);
      var urlStr = isObj ? url.url : url;
      var origUrlStr = urlStr;
      if (typeof urlStr === 'string') {
        urlStr = rewriteUrl(urlStr);
        arguments[0] = urlStr;
      }
      var promise = origFetch.apply(this, arguments);
      if (typeof origUrlStr === 'string' && origUrlStr.indexOf('captchaNotRobot.check') !== -1) {
        promise.then(function(response) {
          return response.clone().json();
        }).then(function(data) {
          if (data.response && data.response.success_token) {
            fetch('` + captchaResultPath + `', {
              method: 'POST',
              headers: {'Content-Type': 'application/x-www-form-urlencoded'},
              body: 'token=' + encodeURIComponent(data.response.success_token)
            }).then(function() {
              window.location = '` + captchaCompletePath + `?status=success';
            });
          }
        }).catch(function() {});
      }
      return promise;
    };
  }
})();
</script>`
}

func captchaCompletionHTML() string {
	return `<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>Captcha complete</title>
  ` + captchaSharedStyle() + `
</head>
<body>
  <div class="captcha-shell">
    <div class="captcha-card">
      <div class="captcha-eyebrow">VK TURN</div>
      <h1>Проверка завершена</h1>
      <p>Окно можно закрыть</p>
    </div>
  </div>
</body>
</html>`
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
