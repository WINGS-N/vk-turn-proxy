package main

import (
	"bytes"
	"context"
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"math/rand"
	"net"
	"strconv"
	"strings"
	"time"

	fhttp "github.com/bogdanfinn/fhttp"
	tlsclient "github.com/bogdanfinn/tls-client"
	"github.com/bogdanfinn/tls-client/profiles"
)

func applyBrowserProfileFhttp(req *fhttp.Request, profile Profile) {
	req.Header.Set("User-Agent", profile.UserAgent)
	req.Header.Set("sec-ch-ua", profile.SecChUa)
	req.Header.Set("sec-ch-ua-mobile", profile.SecChUaMobile)
	req.Header.Set("sec-ch-ua-platform", profile.SecChUaPlatform)
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")
	req.Header.Set("DNT", "1")
}

func generateBrowserFp(profile Profile) string {
	data := profile.UserAgent + profile.SecChUa + "1920x1080x24" + strconv.FormatInt(time.Now().UnixNano(), 10)
	hash := md5.Sum([]byte(data))
	return hex.EncodeToString(hash[:])
}

func generateFakeCursor() string {
	startX := 600 + rand.Intn(400)
	startY := 300 + rand.Intn(200)
	startTime := time.Now().UnixMilli() - int64(rand.Intn(2000)+1000)
	points := make([]string, 0, 24)
	for i := 0; i < 15+rand.Intn(10); i++ {
		startX += rand.Intn(15) - 5
		startY += rand.Intn(15) + 2
		startTime += int64(rand.Intn(40) + 10)
		points = append(points, fmt.Sprintf(`{"x":%d,"y":%d,"t":%d}`, startX, startY, startTime))
	}
	return "[" + strings.Join(points, ",") + "]"
}

func tlsClientProfileFor(profile Profile) profiles.ClientProfile {
	switch {
	case strings.Contains(profile.UserAgent, "Chrome/144"):
		return profiles.Chrome_144
	case strings.Contains(profile.UserAgent, "Chrome/146"):
		return profiles.Chrome_146
	case strings.Contains(profile.UserAgent, "Edg/146"):
		return profiles.Chrome_146
	default:
		return profiles.Chrome_146
	}
}

func (r *protectedResolver) newTLSHTTPClient(profile Profile, timeout time.Duration) (tlsclient.HttpClient, error) {
	return tlsclient.NewHttpClient(
		tlsclient.NewNoopLogger(),
		tlsclient.WithTimeoutMilliseconds(int(timeout/time.Millisecond)),
		tlsclient.WithClientProfile(tlsClientProfileFor(profile)),
		tlsclient.WithCookieJar(tlsclient.NewCookieJar()),
		tlsclient.WithDialer(r.newTLSDialer(timeout)),
		tlsclient.WithNotFollowRedirects(),
		tlsclient.WithRandomTLSExtensionOrder(),
	)
}

func (r *protectedResolver) newTLSDialer(timeout time.Duration) net.Dialer {
	baseDialer := r.dialer()
	baseDialer.Timeout = timeout
	baseDialer.KeepAlive = 30 * time.Second

	resolverAddrs := r.resolverAddrs
	if len(resolverAddrs) == 0 {
		resolverAddrs = defaultResolverAddrs
	}

	return net.Dialer{
		Timeout:   timeout,
		KeepAlive: 30 * time.Second,
		Control:   baseDialer.Control,
		Resolver: &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
				var lastErr error
				for _, resolverAddr := range resolverAddrs {
					conn, err := baseDialer.DialContext(ctx, "udp", resolverAddr)
					if err == nil {
						return conn, nil
					}
					lastErr = err
				}
				if lastErr != nil {
					return nil, lastErr
				}
				return nil, fmt.Errorf("no DNS resolvers available")
			},
		},
	}
}

func newFHTTPRequest(ctx context.Context, method, rawURL string, body []byte) (*fhttp.Request, error) {
	if body == nil {
		return fhttp.NewRequestWithContext(ctx, method, rawURL, nil)
	}
	return fhttp.NewRequestWithContext(ctx, method, rawURL, bytes.NewReader(body))
}
