package wrap

import (
	"bytes"
	"net"
	"testing"
	"time"

	"github.com/cacggghp/vk-turn-proxy/sessionproto"
)

func newStatefulPair(t *testing.T) (*StatefulConn, *StatefulConn, net.PacketConn, net.PacketConn) {
	t.Helper()

	server, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen server: %v", err)
	}
	client, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		_ = server.Close()
		t.Fatalf("listen client: %v", err)
	}
	return NewStateful(client), NewStateful(server), client, server
}

func TestStatefulPassThroughBeforeEnable(t *testing.T) {
	wc, ws, client, server := newStatefulPair(t)
	defer func() { _ = client.Close() }()
	defer func() { _ = server.Close() }()

	// DTLS-shaped payload (ContentType = 22 = handshake).
	payload := append([]byte{0x16}, bytes.Repeat([]byte{0xAB}, 60)...)
	if err := wc.SetWriteDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := wc.WriteTo(payload, server.LocalAddr()); err != nil {
		t.Fatalf("WriteTo: %v", err)
	}
	if err := ws.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 4096)
	n, _, err := ws.ReadFrom(buf)
	if err != nil {
		t.Fatalf("ReadFrom: %v", err)
	}
	if !bytes.Equal(payload, buf[:n]) {
		t.Fatalf("pass-through mismatch: got %x want %x", buf[:n], payload)
	}
}

func TestStatefulRoundTripAfterEnable(t *testing.T) {
	wc, ws, client, server := newStatefulPair(t)
	defer func() { _ = client.Close() }()
	defer func() { _ = server.Close() }()

	key := mustKey(t)
	factory, err := NewFactory(sessionproto.WrapCipher_WRAP_CIPHER_SRTP_AES_256_GCM, key)
	if err != nil {
		t.Fatal(err)
	}
	clientCipher, err := factory.NewConn(false)
	if err != nil {
		t.Fatal(err)
	}
	serverCipher, err := factory.NewConn(true)
	if err != nil {
		t.Fatal(err)
	}
	wc.Enable(clientCipher)
	ws.Enable(serverCipher)

	payload := []byte("application data after wrap negotiation")
	if err = wc.SetWriteDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err = wc.WriteTo(payload, server.LocalAddr()); err != nil {
		t.Fatalf("WriteTo: %v", err)
	}
	if err = ws.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 4096)
	n, _, err := ws.ReadFrom(buf)
	if err != nil {
		t.Fatalf("ReadFrom: %v", err)
	}
	if !bytes.Equal(payload, buf[:n]) {
		t.Fatalf("decrypted payload mismatch: got %q want %q", buf[:n], payload)
	}
}

// TestStatefulMixedReceive simulates the brief window during mu/v1
// negotiation where one peer has already enabled wrap while the other
// is still sending raw DTLS records. The receiver must auto-detect each
// packet independently and never desynchronize.
func TestStatefulMixedReceive(t *testing.T) {
	wc, ws, client, server := newStatefulPair(t)
	defer func() { _ = client.Close() }()
	defer func() { _ = server.Close() }()

	key := mustKey(t)
	factory, err := NewFactory(sessionproto.WrapCipher_WRAP_CIPHER_SRTP_AES_256_GCM, key)
	if err != nil {
		t.Fatal(err)
	}
	clientCipher, err := factory.NewConn(false)
	if err != nil {
		t.Fatal(err)
	}
	serverCipher, err := factory.NewConn(true)
	if err != nil {
		t.Fatal(err)
	}

	rawRecord := append([]byte{0x17}, bytes.Repeat([]byte{0x11}, 30)...) // ContentType=23 (app_data)
	wrappedPayload := []byte("after-enable record")

	// Phase 1: send raw while both sides are pass-through.
	if _, err = wc.WriteTo(rawRecord, server.LocalAddr()); err != nil {
		t.Fatal(err)
	}
	// Phase 2: client enables, server still in pass-through.
	wc.Enable(clientCipher)
	if _, err = wc.WriteTo(wrappedPayload, server.LocalAddr()); err != nil {
		t.Fatal(err)
	}
	// Server enables AFTER it has already seen both packets queued.
	ws.Enable(serverCipher)

	if err = ws.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 4096)

	// First read: raw DTLS record (pass-through).
	n, _, err := ws.ReadFrom(buf)
	if err != nil {
		t.Fatalf("ReadFrom raw: %v", err)
	}
	if !bytes.Equal(rawRecord, buf[:n]) {
		t.Fatalf("raw record corrupted: got %x want %x", buf[:n], rawRecord)
	}

	// Second read: SRTP-wrapped payload (decrypted because cipher is now installed).
	n, _, err = ws.ReadFrom(buf)
	if err != nil {
		t.Fatalf("ReadFrom wrapped: %v", err)
	}
	if !bytes.Equal(wrappedPayload, buf[:n]) {
		t.Fatalf("wrapped payload mismatch: got %q want %q", buf[:n], wrappedPayload)
	}
}

func TestPacketConnRoundTrip(t *testing.T) {
	key := mustKey(t)

	server, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen server: %v", err)
	}
	defer func() { _ = server.Close() }()

	client, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen client: %v", err)
	}
	defer func() { _ = client.Close() }()

	factory, err := NewFactory(sessionproto.WrapCipher_WRAP_CIPHER_SRTP_AES_256_GCM, key)
	if err != nil {
		t.Fatal(err)
	}
	clientCipher, err := factory.NewConn(false)
	if err != nil {
		t.Fatal(err)
	}
	serverCipher, err := factory.NewConn(true)
	if err != nil {
		t.Fatal(err)
	}

	wc := PacketConn(client, clientCipher)
	ws := PacketConn(server, serverCipher)

	payload := []byte("vk-turn SRTP-mimicry packet conn round-trip — should arrive intact")
	if err = wc.SetWriteDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err = wc.WriteTo(payload, server.LocalAddr()); err != nil {
		t.Fatalf("WriteTo: %v", err)
	}

	if err = ws.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 4096)
	n, _, err := ws.ReadFrom(buf)
	if err != nil {
		t.Fatalf("ReadFrom: %v", err)
	}
	if !bytes.Equal(payload, buf[:n]) {
		t.Fatalf("decrypted payload mismatch: got %q want %q", buf[:n], payload)
	}
}

func TestPacketConnNilCipherPassthrough(t *testing.T) {
	inner, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = inner.Close() }()
	if got := PacketConn(inner, nil); got != inner {
		t.Fatalf("PacketConn(inner, nil) should return inner verbatim, got %T", got)
	}
}
