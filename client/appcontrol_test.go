package main

import (
	"context"
	"errors"
	"net"
	"path/filepath"
	"testing"

	"github.com/cacggghp/vk-turn-proxy/appcontrolpb"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

func TestAppControl(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "app.sock")
	var gotCookies, gotUA string
	gs, err := StartAppControl(sock, "s3cret", -1, "",
		func(cookies, ua string) { gotCookies, gotUA = cookies, ua },
		func(_ context.Context, clientID string, token []byte, _ string, _ uint32) (*appcontrolpb.WireguardConfig, error) {
			if clientID != "c1" || string(token) != "tok" {
				return nil, errors.New("bad request")
			}
			return &appcontrolpb.WireguardConfig{PrivateKey: "priv", Address: "10.66.66.2/32", Mtu: 1280}, nil
		},
		nil)
	if err != nil {
		t.Fatalf("StartAppControl: %v", err)
	}
	t.Cleanup(gs.Stop)

	conn, err := grpc.NewClient(
		"passthrough:///app",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", sock)
		}),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	client := appcontrolpb.NewAppControlClient(conn)

	if _, err := client.SetVKCookies(context.Background(), &appcontrolpb.SetVKCookiesRequest{}); status.Code(err) != codes.Unauthenticated {
		t.Fatalf("without token: code = %v, want Unauthenticated", status.Code(err))
	}

	authed := metadata.AppendToOutgoingContext(context.Background(), "authorization", "Bearer s3cret")
	if _, err := client.SetVKCookies(authed, &appcontrolpb.SetVKCookiesRequest{Cookies: "ck", UserAgent: "ua"}); err != nil {
		t.Fatalf("SetVKCookies: %v", err)
	}
	if gotCookies != "ck" || gotUA != "ua" {
		t.Fatalf("cookies not delivered: %q / %q", gotCookies, gotUA)
	}

	resp, err := client.Provision(authed, &appcontrolpb.ProvisionRequest{ClientId: "c1", Token: []byte("tok"), Hwid: "hw"})
	if err != nil {
		t.Fatalf("Provision: %v", err)
	}
	if resp.GetError() != "" || resp.GetWg().GetPrivateKey() != "priv" || resp.GetWg().GetAddress() != "10.66.66.2/32" {
		t.Fatalf("provision result wrong: %+v", resp)
	}

	setVkCookies("realck", "realua")
	got, err := client.GetVKCookies(authed, &appcontrolpb.GetVKCookiesRequest{})
	if err != nil {
		t.Fatalf("GetVKCookies: %v", err)
	}
	if got.GetCookies() != "realck" || got.GetUserAgent() != "realua" {
		t.Fatalf("GetVKCookies returned %q / %q", got.GetCookies(), got.GetUserAgent())
	}
}
