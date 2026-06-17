package dnsdial

import (
	"context"
	"errors"
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

	// Poison udpDNSServers so the UDP probe fails - udpDNSDial rejects the
	// malformed address; auto then validates DoH (mock) and sticks to it.
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

	// Second call must skip UDP entirely (sticky within autoReevalInterval -
	// maybeReeval is rate-gated, so no re-probe touches UDP here). We assert this
	// by poisoning udpDNSServers with a value that would fail parsing.
	bad2 := []string{"still-not-a-valid-host-port"}
	udpDNSServersPtr.Store(&bad2)
	conn2, err := dial(ctx, "udp", "unused")
	if err != nil {
		t.Fatalf("second dial: %v", err)
	}
	_ = conn2.Close()
}

// startFakeUDPDNS поднимает локальный UDP DNS, отвечающий на A-запрос фиксированным
// answer (nil -> NOERROR без записей). Возвращает адрес ip:port.
func startFakeUDPDNS(t *testing.T, answer net.IP) string {
	t.Helper()
	pc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("listen udp: %v", err)
	}
	t.Cleanup(func() { _ = pc.Close() })
	go func() {
		buf := make([]byte, 1024)
		for {
			n, addr, rerr := pc.ReadFromUDP(buf)
			if rerr != nil {
				return
			}
			req := new(dns.Msg)
			if req.Unpack(buf[:n]) != nil {
				continue
			}
			reply := new(dns.Msg)
			reply.SetReply(req)
			if answer != nil && len(req.Question) == 1 && req.Question[0].Qtype == dns.TypeA {
				if v4 := answer.To4(); v4 != nil {
					reply.Answer = append(reply.Answer, &dns.A{
						Hdr: dns.RR_Header{Name: req.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
						A:   v4,
					})
				}
			}
			out, perr := reply.Pack()
			if perr != nil {
				continue
			}
			_, _ = pc.WriteToUDP(out, addr)
		}
	}()
	return pc.LocalAddr().String()
}

func TestProbeResolves(t *testing.T) {
	cases := []struct {
		name   string
		answer net.IP // nil -> NOERROR без A-записей (домен дропнут/отфильтрован)
		want   bool
	}{
		{"valid public A", net.ParseIP("93.184.216.34"), true},
		{"poisoned unspecified", net.ParseIP("0.0.0.0"), false},
		{"no answer", nil, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			server := startFakeUDPDNS(t, tc.answer)
			old := udpDNSServersPtr.Load()
			s := []string{server}
			udpDNSServersPtr.Store(&s)
			defer udpDNSServersPtr.Store(old)

			if got := probeResolves(udpDNSDial, "login.vk.ru", 2*time.Second); got != tc.want {
				t.Errorf("probeResolves(%s) = %v, want %v", tc.name, got, tc.want)
			}
		})
	}
}

func failDial(context.Context, string, string) (net.Conn, error) {
	return nil, errors.New("dial unavailable")
}

// UDP не резолвит цель и DoH-проба тоже падает -> auto залипает на DoH.
func TestAutoState_FailsOverToDoH(t *testing.T) {
	a := &autoState{udpDial: udpDNSDial, dohDial: failDial, host: func() string { return "login.vk.ru" }}

	old := udpDNSServersPtr.Load()
	bad := []string{"not-a-valid-host-port"}
	udpDNSServersPtr.Store(&bad)
	defer udpDNSServersPtr.Store(old)

	a.decide(true)
	if !a.useDoH.Load() {
		t.Fatal("expected sticky DoH when UDP can't resolve target")
	}
}

// Залипли на DoH, UDP снова резолвит цель -> перепроба возвращает на UDP (recovery).
func TestAutoState_RecoversToUDP(t *testing.T) {
	a := &autoState{udpDial: udpDNSDial, dohDial: failDial, host: func() string { return "login.vk.ru" }}
	a.useDoH.Store(true) // имитируем залипание на DoH

	server := startFakeUDPDNS(t, net.ParseIP("93.184.216.34"))
	old := udpDNSServersPtr.Load()
	s := []string{server}
	udpDNSServersPtr.Store(&s)
	defer udpDNSServersPtr.Store(old)

	a.decide(false)
	if a.useDoH.Load() {
		t.Fatal("expected switch back to UDP after target resolves over UDP again")
	}
}
