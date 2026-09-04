package main

import (
	"strings"
	"testing"
)

// Релей федерации обязан отдавать трафик своему же WireGuard: только там его
// видно наблюдению и только там его режет шейпер
func TestFederationRefusesForeignBackend(t *testing.T) {
	cases := []struct {
		name string
		opts serverOptions
		want string
	}{
		{
			name: "чужой хост",
			opts: serverOptions{federation: true, wgApply: true, udpConnect: "10.8.0.1:51820", wgListenPort: 51820},
			want: "only the loopback",
		},
		{
			name: "чужой порт",
			opts: serverOptions{federation: true, wgApply: true, udpConnect: "127.0.0.1:51821", wgListenPort: 51820},
			want: "managed WireGuard listens",
		},
		{
			name: "без своего wg",
			opts: serverOptions{federation: true, udpConnect: "127.0.0.1:51820", wgListenPort: 51820},
			want: "requires -wg-apply",
		},
		{
			name: "путь tcp",
			opts: serverOptions{federation: true, wgApply: true, tcpConnect: "127.0.0.1:51820", wgListenPort: 51820},
			want: "refuses a TCP backend",
		},
		{
			name: "комната wb-stream",
			opts: serverOptions{federation: true, wgApply: true, wbStreamRoomID: "ABC", udpConnect: "127.0.0.1:51820", wgListenPort: 51820},
			want: "wb-stream-room-id",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := checkFederationBackend(tc.opts)
			if err == nil {
				t.Fatalf("увод пропущен: %+v", tc.opts)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("не та причина: %v", err)
			}
		})
	}
}

func TestFederationAllowsManagedWireguard(t *testing.T) {
	opts := serverOptions{federation: true, wgApply: true, udpConnect: "127.0.0.1:51820", wgListenPort: 51820}
	if err := checkFederationBackend(opts); err != nil {
		t.Fatalf("свой wg завернули: %v", err)
	}
	// Без режима федерации внешний бэкенд законен: релей донора живёт своей
	// жизнью и федерации не касается
	plain := serverOptions{udpConnect: "10.8.0.1:51820"}
	if err := checkFederationBackend(plain); err != nil {
		t.Fatalf("обычный релей задет: %v", err)
	}
}
