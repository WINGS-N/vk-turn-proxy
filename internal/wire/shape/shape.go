// Package shape реализует packet pacing для RTP-мимикрии:
// задержка между отправкой пакетов + случайный jitter.
// Оборачивает net.PacketConn, вставляя sleep перед каждым WriteTo.
// Совместим с любой стороной — пакеты те же, только медленнее.
//
// Поддерживает два режима jitter:
//   - Uniform (±10%): стандартный, как в v1/v2 (rate=1.0)
//   - Gaussian: более естественное распределение задержек (rate=2.0)
package shape

import (
	"math"
	"net"
	"time"

	dtlsnet "github.com/pion/dtls/v3/pkg/net"

	"github.com/samosvalishe/free-turn-proxy/internal/randx"
)

// JitterModel определяет распределение случайной добавки к задержке.
type JitterModel int

const (
	JitterUniform  JitterModel = iota // ±rate% от interval (0..2*rate*interval)
	JitterGaussian                    // гауссово распределение с sigma = rate*interval/3
)

// Shaper управляет межпакетной задержкой.
type Shaper struct {
	interval  time.Duration
	lastSend  time.Time
	model     JitterModel
	jitterPct float64 // доля interval для jitter (0.1 = ±10%)
	burst     int     // осталось пакетов в текущем burst (0 = не в burst)
	burstMax  int     // макс. пакетов в burst
}

// New создаёт Shaper. interval=0 отключает pacing.
func New(interval time.Duration) *Shaper {
	return &Shaper{
		interval:  interval,
		model:     JitterUniform,
		jitterPct: 0.10,
		burstMax:  3,
	}
}

// SetJitterModel меняет модель jitter.
func (s *Shaper) SetJitterModel(m JitterModel) { s.model = m }

// SetJitterPct задаёт долю interval для jitter (0.0-0.5).
func (s *Shaper) SetJitterPct(pct float64) {
	if pct < 0 {
		pct = 0
	}
	if pct > 0.5 {
		pct = 0.5
	}
	s.jitterPct = pct
}

// SetBurst ограничивает макс. число пакетов без задержки (WebRTC-подобные мини-батчи).
// 0 = отключено (каждый пакет с задержкой).
func (s *Shaper) SetBurst(max int) {
	if max < 0 {
		max = 0
	}
	s.burstMax = max
}

// Wait блокируется до момента, когда можно отправить следующий пакет.
func (s *Shaper) Wait() {
	if s.interval <= 0 {
		return
	}
	// Burst-режим: первые burstMax пакетов идут без задержки.
	if s.burst > 0 {
		s.burst--
		s.lastSend = time.Now()
		return
	}
	if s.burstMax > 0 {
		// Случайно начинаем новый burst.
		if randx.Intn(100) < 30 { // 30% шанс начать burst
			s.burst = 1 + randx.Intn(s.burstMax)
			s.burst--
			s.lastSend = time.Now()
			return
		}
	}

	elapsed := time.Since(s.lastSend)
	wait := s.interval - elapsed
	if wait <= 0 {
		s.lastSend = time.Now()
		return
	}

	switch s.model {
	case JitterUniform:
		jitter := time.Duration(float64(s.interval) * s.jitterPct)
		if jitter > 0 {
			wait += time.Duration(randx.Intn(int(jitter)*2+1)) - jitter
		}
	case JitterGaussian:
		// Гауссов jitter: box-muller из uniform(0,1).
		sigma := float64(s.interval) * s.jitterPct / 3.0
		u1 := float64(randx.Intn(1<<31-1)) / (1 << 31)
		u2 := float64(randx.Intn(1<<31-1)) / (1 << 31)
		if u1 < 1e-15 {
			u1 = 1e-15
		}
		z := math.Sqrt(-2*math.Log(u1)) * math.Cos(2*math.Pi*u2)
		wait += time.Duration(z * sigma)
	}
	if wait < 0 {
		wait = 0
	}
	time.Sleep(wait)
	s.lastSend = time.Now()
}

// ShapedPacketConn оборачивает net.PacketConn, применяя pacing к WriteTo.
// ReadFrom, Close и остальные методы пробрасываются без изменений.
type ShapedPacketConn struct {
	net.PacketConn
	shaper *Shaper
}

// WrapPacketConn оборачивает conn с межпакетной задержкой interval.
// interval=0 возвращает conn без обёртки (passthrough).
func WrapPacketConn(conn net.PacketConn, interval time.Duration) net.PacketConn {
	if interval <= 0 {
		return conn
	}
	return &ShapedPacketConn{
		PacketConn: conn,
		shaper:     New(interval),
	}
}

// WriteTo применяет pacing перед отправкой.
func (s *ShapedPacketConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	s.shaper.Wait()
	return s.PacketConn.WriteTo(b, addr)
}

// shapedPacketConnAdapter адаптирует PacketConn с shaping-ом для
// использования в качестве возвращаемого значения dtlsnet.PacketListener.Accept().
type shapedPacketConnAdapter struct {
	net.PacketConn
	writeShaper *Shaper
}

func (a *shapedPacketConnAdapter) WriteTo(b []byte, addr net.Addr) (int, error) {
	a.writeShaper.Wait()
	return a.PacketConn.WriteTo(b, addr)
}

// shapedPacketListener оборачивает dtlsnet.PacketListener, применяя pacing
// к WriteTo каждого принятого PacketConn.
type shapedPacketListener struct {
	inner  dtlsnet.PacketListener
	shaper *Shaper
}

// Accept принимает соединение и оборачивает его ShapedPacketConn.
func (l *shapedPacketListener) Accept() (net.PacketConn, net.Addr, error) {
	pc, addr, err := l.inner.Accept()
	if err != nil {
		return pc, addr, err
	}
	return &shapedPacketConnAdapter{
		PacketConn:  pc,
		writeShaper: New(l.shaper.interval),
	}, addr, nil
}

func (l *shapedPacketListener) Close() error   { return l.inner.Close() }
func (l *shapedPacketListener) Addr() net.Addr { return l.inner.Addr() }

// WrapPacketListener оборачивает dtlsnet.PacketListener, добавляя pacing
// к WriteTo каждого принятого PacketConn (server-side shaping).
// interval=0 возвращает оригинальный listener без обёртки.
func WrapPacketListener(l dtlsnet.PacketListener, interval time.Duration) dtlsnet.PacketListener {
	if interval <= 0 {
		return l
	}
	return &shapedPacketListener{
		inner:  l,
		shaper: New(interval),
	}
}
