package relaygrpc

import (
	"context"
	"net"
	"sync"
	"time"

	"github.com/pion/stun/v3"
)

// stunServers - куда спрашивать свой внешний адрес. Несколько, потому что один
// может не ответить, а без адреса релей не знает, что писать клиентам
var stunServers = []string{
	"stun.l.google.com:19302",
	"stun.cloudflare.com:3478",
	"stun1.l.google.com:19302",
}

// refreshEvery - как часто адрес перепроверяется. Провайдер меняет его без
// предупреждения, и устаревшая запись ведёт клиентов в никуда
const refreshEvery = 30 * time.Minute

// SelfAddress держит внешний адрес релея, узнанный у STUN
type SelfAddress struct {
	mu      sync.RWMutex
	addr    string
	checked time.Time
}

// NewSelfAddress создаёт пустой держатель
func NewSelfAddress() *SelfAddress { return &SelfAddress{} }

// Get возвращает последний известный адрес
func (s *SelfAddress) Get() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.addr
}

// Run обновляет адрес, пока не кончится ctx
func (s *SelfAddress) Run(ctx context.Context) {
	s.refresh(ctx)
	ticker := time.NewTicker(refreshEvery)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.refresh(ctx)
		}
	}
}

func (s *SelfAddress) refresh(ctx context.Context) {
	for _, server := range stunServers {
		// Спрашиваем именно по IPv4: до подавляющего большинства людей
		// дотягивается только он, а хост с двойным стеком иначе отвечает
		// адресом, по которому к нему почти никто не придёт
		addr, err := askSTUN(ctx, server)
		if err != nil || addr == "" {
			continue
		}
		s.mu.Lock()
		s.addr, s.checked = addr, time.Now()
		s.mu.Unlock()
		return
	}
}

// askSTUN спрашивает один сервер. Ответ - тот адрес, каким релея видит интернет,
// а не тот, что он видит на своих интерфейсах
func askSTUN(ctx context.Context, server string) (string, error) {
	dialer := net.Dialer{Timeout: 5 * time.Second}
	conn, err := dialer.DialContext(ctx, "udp4", server)
	if err != nil {
		return "", err
	}
	defer func() { _ = conn.Close() }()

	client, err := stun.NewClient(conn)
	if err != nil {
		return "", err
	}
	defer func() { _ = client.Close() }()

	var found string
	message := stun.MustBuild(stun.TransactionID, stun.BindingRequest)
	err = client.Do(message, func(res stun.Event) {
		if res.Error != nil {
			return
		}
		var mapped stun.XORMappedAddress
		if mapped.GetFrom(res.Message) == nil {
			found = mapped.IP.String()
		}
	})
	if err != nil {
		return "", err
	}
	return found, nil
}
