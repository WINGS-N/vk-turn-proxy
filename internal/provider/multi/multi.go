// Package multi - MultiProvider: объединяет несколько provider.Provider
// в один, распределяя streamID по всем провайдерам round-robin.
// Позволяет использовать несколько VK-звонков одновременно для пула TURN-стримов.
package multi

import (
	"context"
	"fmt"

	"github.com/samosvalishe/free-turn-proxy/internal/provider"
)

// TCP mode (-mode tcp):
// Локальный TCP-поток (Xray)
//
//	 │
//	├─ без bond: pool.Pick() → round-robin по всем 30 smux-сессиям
//	 └─ с bond:   bondclient.Handle → страйпинг по всем 30 сессиям
//	                   │
//	                   │  Каждая smux-сессия:
//	                   │    DTLS → KCP → TURN allocate → Server DTLS
//	                   │
//	                   ▼
//	           Backend (Xray TCP)
//
// UDP mode (-mode udp):
// Локальный UDP (WireGuard)
//
//	  │
//	  ▼
//	inboundChan → broadcast во все 30 DTLS-стримов
//	                    │
//	                    │  Каждый DTLS-стрим:
//	                    │    (DTLS) → OBF → TURN allocate → Server DTLS
//	                    │
//	                    ▼
//	           Backend (WireGuard UDP)
//
// MultiProvider распределяет streamID по вложенным провайдерам.
// StreamID 1-based: (streamID-1) % n → выбор провайдера.
// Внутренний streamID: ((streamID-1) / n) + 1 → передаётся выбранному провайдеру.
//
// Например, 3 провайдера × 10 стримов = 30 стримов:
//
//	streamID 1,4,7,10,13,16,19,22,25,28 → provider[0] (internal 1..10)
//	streamID 2,5,8,11,14,17,20,23,26,29 → provider[1] (internal 1..10)
//	streamID 3,6,9,12,15,18,21,24,27,30 → provider[2] (internal 1..10)
type MultiProvider struct {
	providers []provider.Provider
	n         int
}

// New создаёт MultiProvider. Паникует если providers пуст.
func New(providers []provider.Provider) *MultiProvider {
	if len(providers) == 0 {
		panic("multi: empty providers")
	}
	return &MultiProvider{
		providers: providers,
		n:         len(providers),
	}
}

// providerFor возвращает провайдера и внутренний streamID для глобального streamID.
func (m *MultiProvider) providerFor(streamID int) (provider.Provider, int) {
	idx := (streamID - 1) % m.n
	innerID := ((streamID - 1) / m.n) + 1
	return m.providers[idx], innerID
}

// GetCredentials делегирует выбранному провайдеру.
func (m *MultiProvider) GetCredentials(ctx context.Context, streamID int) (provider.Credentials, error) {
	p, innerID := m.providerFor(streamID)
	return p.GetCredentials(ctx, innerID)
}

// IsAuthError делегирует первому провайдеру (все VK провайдеры используют
// одинаковую эвристику auth-ошибки — проверку строки ошибки).
func (m *MultiProvider) IsAuthError(err error) bool {
	return m.providers[0].IsAuthError(err)
}

// HandleAuthError делегирует провайдеру, соответствующему streamID.
func (m *MultiProvider) HandleAuthError(streamID int) bool {
	p, innerID := m.providerFor(streamID)
	return p.HandleAuthError(innerID)
}

// ResetErrors делегирует провайдеру, соответствующему streamID.
func (m *MultiProvider) ResetErrors(streamID int) {
	p, innerID := m.providerFor(streamID)
	p.ResetErrors(innerID)
}

// BackoffUntilUnix возвращает максимальный backoff среди всех провайдеров.
// Консервативно: если хотя бы один провайдер в блокировке, все стримы
// делают короткую паузу вместо tight-spin.
func (m *MultiProvider) BackoffUntilUnix() int64 {
	var max int64
	for _, p := range m.providers {
		if v := p.BackoffUntilUnix(); v > max {
			max = v
		}
	}
	return max
}

// Name возвращает "multi(N)".
func (m *MultiProvider) Name() string {
	return fmt.Sprintf("multi(%d)", m.n)
}
