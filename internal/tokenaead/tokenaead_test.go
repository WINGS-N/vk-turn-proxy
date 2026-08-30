package tokenaead

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"net"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
)

const token = "s3cr3t-token-abc"

func startServer(t *testing.T, creds credentials.TransportCredentials) string {
	t.Helper()
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := grpc.NewServer(grpc.Creds(creds))
	healthpb.RegisterHealthServer(srv, health.NewServer())
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(srv.Stop)
	return lis.Addr().String()
}

func dialCheck(t *testing.T, addr string, creds credentials.TransportCredentials) error {
	t.Helper()
	conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(creds))
	if err != nil {
		return err
	}
	defer func() { _ = conn.Close() }()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_, err = healthpb.NewHealthClient(conn).Check(ctx, &healthpb.HealthCheckRequest{})
	return err
}

// The whole point of the migration: one listener serves both a panel that has
// moved to SHA-512 and one that has not, so nodes and panels update on their own
// schedules instead of in one flag day.
func TestDualServerAcceptsBothDerivations(t *testing.T) {
	addr := startServer(t, ServerAny(token, SHA512, Legacy256))
	for _, tc := range []struct {
		name    string
		variant Variant
	}{
		{"updated client", SHA512},
		{"deployed client", Legacy256},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := dialCheck(t, addr, ClientVariant(token, tc.variant)); err != nil {
				t.Fatalf("%s could not talk to the dual listener: %v", tc.name, err)
			}
		})
	}
}

// A wrong token must still fail, and must fail the same way whichever
// derivation it used - accepting two derivations may not become accepting two
// chances at the token.
func TestDualServerStillRejectsAWrongToken(t *testing.T) {
	addr := startServer(t, ServerAny(token, SHA512, Legacy256))
	for _, v := range []Variant{SHA512, Legacy256} {
		if err := dialCheck(t, addr, ClientVariant("WRONG-token-xyz", v)); err == nil {
			t.Fatalf("a wrong token was accepted on %s", v)
		}
	}
}

// A single-derivation listener keeps the old behaviour exactly, which is what
// every already-deployed peer is talking to.
func TestSingleDerivationListenerIsUnchanged(t *testing.T) {
	addr := startServer(t, Server(token))
	if err := dialCheck(t, addr, Client(token)); err != nil {
		t.Fatalf("legacy pairing broke: %v", err)
	}
	if err := dialCheck(t, addr, ClientVariant(token, SHA512)); err == nil {
		t.Fatal("a legacy-only listener accepted a SHA-512 client")
	}
}

func TestVariantsDoNotInteroperate(t *testing.T) {
	if bytes.Equal(
		deriveKey(Legacy256, []byte(token), "c2s"),
		deriveKey(SHA512, []byte(token), "c2s"),
	) {
		t.Fatal("both derivations produced the same key")
	}
}

// The length prefix arrives before anything is authenticated, so an unbounded
// one lets a peer that holds no token make the server allocate 4 GiB.
func TestOversizedRecordIsRefusedBeforeAllocating(t *testing.T) {
	client, server := net.Pipe()
	defer func() { _ = client.Close() }()
	defer func() { _ = server.Close() }()

	go func() {
		var hdr [4]byte
		binary.BigEndian.PutUint32(hdr[:], 0xFFFFFFFF)
		_, _ = client.Write(hdr[:])
	}()
	if _, err := readRecord(server); err == nil {
		t.Fatal("a 4 GiB length prefix was accepted")
	}

	go func() {
		var hdr [4]byte
		binary.BigEndian.PutUint32(hdr[:], 0)
		_, _ = client.Write(hdr[:])
	}()
	if _, err := readRecord(server); err == nil {
		t.Fatal("an empty record was accepted")
	}
}

// Knowing which peers are still on the old derivation is the only way to know
// when the legacy path can be dropped.
func TestNegotiatedVariantIsReported(t *testing.T) {
	for _, want := range []Variant{SHA512, Legacy256} {
		client, server := net.Pipe()
		errs := make(chan error, 1)
		go func() {
			wrapped, _, err := ClientVariant(token, want).ClientHandshake(context.Background(), "", client)
			if err != nil {
				errs <- err
				return
			}
			// The server resolves on the first record, so one has to arrive.
			_, err = wrapped.Write([]byte("hello"))
			errs <- err
		}()

		_, info, err := ServerAny(token, SHA512, Legacy256).ServerHandshake(server)
		if err != nil {
			t.Fatalf("%s handshake: %v", want, err)
		}
		if got, ok := NegotiatedVariant(info); !ok || got != want {
			t.Errorf("negotiated %v (ok=%v), want %v", got, ok, want)
		}
		if err := <-errs; err != nil {
			t.Errorf("%s client write: %v", want, err)
		}
		_ = client.Close()
		_ = server.Close()
	}
}

// This package exists in four repositories - the panel, the federation head and
// agent, the 3x-ui fork and the vk-turn-proxy relay - and every pair of them has
// to derive identical keys or the management channel silently stops connecting.
// These vectors are the cheap way to catch a copy drifting: they are the same
// literals in all four, so a change that only lands in one fails there.
func TestKeyDerivationFixture(t *testing.T) {
	const fixtureSecret = "interop-fixture-secret"
	for _, tc := range []struct {
		variant Variant
		c2s     string
	}{
		{Legacy256, "2118ec3bf68fdafbe7114b757123a0b32ea1b53399fcd017a4a1bc04940352c5"},
		{SHA512, "2697bf261454d5cace02abca3205991d3d77c4ea73f257d57459252285603eaf"},
	} {
		got := hex.EncodeToString(deriveKey(tc.variant, []byte(fixtureSecret), "c2s"))
		if got != tc.c2s {
			t.Errorf("%s c2s = %s, want %s (this copy has drifted from the other repositories)", tc.variant, got, tc.c2s)
		}
	}
}
