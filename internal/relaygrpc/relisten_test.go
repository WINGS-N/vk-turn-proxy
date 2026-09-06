package relaygrpc

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/cacggghp/vk-turn-proxy/controlpb"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestReloadMovesTheListenAddress(t *testing.T) {
	current := "0.0.0.0:56000"
	var gotDrain time.Duration
	s := &server{
		listen:     current,
		listenAddr: func() string { return current },
		relisten: func(addr string, drain time.Duration) (string, error) {
			gotDrain = drain
			current = addr
			return addr, nil
		},
	}
	resp, err := s.Reload(context.Background(), &controlpb.ReloadRequest{
		Listen:       "0.0.0.0:41337",
		DrainSeconds: 30,
	})
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if resp.GetListen() != "0.0.0.0:41337" {
		t.Fatalf("ответ несёт %q, а переехали на 0.0.0.0:41337", resp.GetListen())
	}
	if gotDrain != 30*time.Second {
		t.Fatalf("дренаж %s, а просили 30s", gotDrain)
	}
	if len(resp.GetApplied()) != 1 || resp.GetApplied()[0] != "listen" {
		t.Fatalf("applied=%v, а переезд состоялся", resp.GetApplied())
	}
	for _, item := range resp.GetRestartRequired() {
		if item == "listen" {
			t.Fatal("listen требует рестарта, хотя он применён на лету")
		}
	}
	if resp.GetConfigVersion() == 0 {
		t.Fatal("версия конфига не выросла на применённой правке")
	}
}

// Занятый порт обязан быть отказом вызывающему: релей при этом продолжает
// принимать на прежнем адресе, и молчаливый простой тут хуже ошибки
func TestReloadRefusesABusyPort(t *testing.T) {
	s := &server{
		listen:     "0.0.0.0:56000",
		listenAddr: func() string { return "0.0.0.0:56000" },
		relisten: func(string, time.Duration) (string, error) {
			return "", errors.New("address already in use")
		},
	}
	_, err := s.Reload(context.Background(), &controlpb.ReloadRequest{Listen: "0.0.0.0:80"})
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("код ошибки %s, а ждали FailedPrecondition", status.Code(err))
	}
}

// Релей без поддержки переезда говорит прямо, а не делает вид, что применил
func TestReloadWithoutRelistenSaysRestart(t *testing.T) {
	s := &server{listen: "0.0.0.0:56000"}
	resp, err := s.Reload(context.Background(), &controlpb.ReloadRequest{Listen: "0.0.0.0:41337"})
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	found := false
	for _, item := range resp.GetRestartRequired() {
		if item == "listen" {
			found = true
		}
	}
	if !found {
		t.Fatalf("restart_required=%v, а переезд не поддержан", resp.GetRestartRequired())
	}
	if resp.GetListen() != "0.0.0.0:56000" {
		t.Fatalf("ответ несёт %q, а слушаем 0.0.0.0:56000", resp.GetListen())
	}
}

// Пустой listen не трогает приём: это обычный перечитывающий Reload
func TestReloadWithoutListenKeepsTheSocket(t *testing.T) {
	moved := false
	s := &server{
		listen:     "0.0.0.0:56000",
		listenAddr: func() string { return "0.0.0.0:56000" },
		relisten: func(string, time.Duration) (string, error) {
			moved = true
			return "", nil
		},
		reload: func(context.Context) ([]string, []string, error) {
			return []string{"peers"}, nil, nil
		},
	}
	resp, err := s.Reload(context.Background(), &controlpb.ReloadRequest{})
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if moved {
		t.Fatal("сокет переехал без просьбы")
	}
	if len(resp.GetApplied()) != 1 || resp.GetApplied()[0] != "peers" {
		t.Fatalf("applied=%v", resp.GetApplied())
	}
}
