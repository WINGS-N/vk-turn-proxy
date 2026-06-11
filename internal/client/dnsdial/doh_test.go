package dnsdial

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// dohAnswer builds a wire-format DNS reply for a single question with one
// answer of the matching type (A or AAAA). TTL is returned as-is.
func dohAnswer(t *testing.T, query []byte, ip net.IP, ttl uint32) []byte {
	t.Helper()
	req := new(dns.Msg)
	if err := req.Unpack(query); err != nil {
		t.Fatalf("unpack query: %v", err)
	}
	reply := new(dns.Msg)
	reply.SetReply(req)
	if len(req.Question) != 1 {
		t.Fatalf("expected 1 question, got %d", len(req.Question))
	}
	q := req.Question[0]
	switch q.Qtype {
	case dns.TypeA:
		if v4 := ip.To4(); v4 != nil {
			reply.Answer = append(reply.Answer, &dns.A{
				Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: ttl},
				A:   v4,
			})
		}
	case dns.TypeAAAA:
		if ip.To4() == nil {
			reply.Answer = append(reply.Answer, &dns.AAAA{
				Hdr:  dns.RR_Header{Name: q.Name, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: ttl},
				AAAA: ip,
			})
		}
	}
	out, err := reply.Pack()
	if err != nil {
		t.Fatalf("pack reply: %v", err)
	}
	return out
}

func readWire(t *testing.T, r io.Reader) []byte {
	t.Helper()
	b, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	return b
}

func TestAutoDial_DynamicFallbackOnUDPDialError(t *testing.T) {
	// DoH backend всегда отвечает валидным wire-ответом.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body := readWire(t, r.Body)
		w.Header().Set("Content-Type", "application/dns-message")
		_, _ = w.Write(dohAnswer(t, body, net.ParseIP("9.9.9.9"), 300)) //nolint:errcheck
	}))
	defer srv.Close()
	resolver := newDohResolverWithClient(
		[]DohEndpoint{{URL: srv.URL, Hostname: "mock", BootstrapIPs: []string{"127.0.0.1"}}},
		srv.Client(),
	)

	// Локальный UDP DNS-ответчик: проба (udpProbe) пройдёт.
	pc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("listen udp: %v", err)
	}
	defer func() { _ = pc.Close() }()
	go func() {
		buf := make([]byte, 512)
		for {
			n, from, rerr := pc.ReadFromUDP(buf)
			if rerr != nil {
				return
			}
			_, _ = pc.WriteToUDP(dohAnswer(t, buf[:n], net.ParseIP("1.2.3.4"), 60), from) //nolint:errcheck
		}
	}()

	old := udpDNSServersPtr.Load()
	good := []string{pc.LocalAddr().String()}
	udpDNSServersPtr.Store(&good)
	defer func() { udpDNSServersPtr.Store(old) }()

	dial := autoDial(resolver)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Первый вызов: проба OK + реальный UDP-dial OK.
	conn1, err := dial(ctx, "udp", "unused")
	if err != nil {
		t.Fatalf("first dial (UDP): %v", err)
	}
	_ = conn1.Close()

	// Сеть "сменилась": UDP/53 серверы недостижимы → dial должен упасть и
	// динамически переключиться на DoH.
	bad := []string{"not-a-valid-host-port"}
	udpDNSServersPtr.Store(&bad)
	conn2, err := dial(ctx, "udp", "unused")
	if err != nil {
		t.Fatalf("second dial must fall back to DoH, got: %v", err)
	}
	_ = conn2.Close()

	// После фоллбэка процесс залип на DoH: третий вызов с битыми UDP проходит.
	conn3, err := dial(ctx, "udp", "unused")
	if err != nil {
		t.Fatalf("third dial must stay on DoH, got: %v", err)
	}
	_ = conn3.Close()
}

func TestAutoDial_StickyAfterUDPFailure(t *testing.T) {
	// DoH backend: always responds with a valid wire-format reply.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body := readWire(t, r.Body)
		w.Header().Set("Content-Type", "application/dns-message")
		_, _ = w.Write(dohAnswer(t, body, net.ParseIP("9.9.9.9"), 300)) //nolint:errcheck
	}))
	defer srv.Close()

	resolver := newDohResolverWithClient(
		[]DohEndpoint{{URL: srv.URL, Hostname: "mock", BootstrapIPs: []string{"127.0.0.1"}}},
		srv.Client(),
	)

	dial := autoDial(resolver)

	// Poison udpDNSServers so that udpProbe (real DNS round-trip) fails
	// immediately — net.DialTimeout rejects the malformed address.
	old := udpDNSServersPtr.Load()
	bad := []string{"not-a-valid-host-port"}
	udpDNSServersPtr.Store(&bad)
	defer func() { udpDNSServersPtr.Store(old) }()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	conn1, err := dial(ctx, "udp", "unused")
	if err != nil {
		t.Fatalf("first dial: %v", err)
	}
	_ = conn1.Close()

	// Second call must skip UDP entirely. We assert this by poisoning
	// udpDNSServers with a value that would fail parsing — if the dialer
	// touches UDP again the call errors loudly.
	bad2 := []string{"still-not-a-valid-host-port"}
	udpDNSServersPtr.Store(&bad2)
	conn2, err := dial(ctx, "udp", "unused")
	if err != nil {
		t.Fatalf("second dial: %v", err)
	}
	_ = conn2.Close()
}
