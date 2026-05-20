package wrap

import (
	"bytes"
	"net"
	"testing"
	"time"

	"github.com/cacggghp/vk-turn-proxy/sessionproto"
)

func TestPacketConnRoundTrip(t *testing.T) {
	key := mustKey(t)

	server, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen server: %v", err)
	}
	defer server.Close()

	client, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen client: %v", err)
	}
	defer client.Close()

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
	defer inner.Close()
	if got := PacketConn(inner, nil); got != inner {
		t.Fatalf("PacketConn(inner, nil) should return inner verbatim, got %T", got)
	}
}
