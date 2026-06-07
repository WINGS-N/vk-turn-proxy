package turndial

import (
	"strings"
	"sync"

	"github.com/pion/logging"
)

// VK relay при дропе permission молча роняет пакеты к peer без ошибки записи.
// pion на каждый проваленный цикл refresh пишет permFailMarker (Warnf, scope
// "turnc"). Считаем провалы подряд — точный per-stream детект блэкхола вместо
// трафик-эвристики (обратный путь WG привязан к endpoint, не к стриму).
const (
	permFailMarker = "Failed to refresh permissions"
	permOKMarker   = "Refresh permissions successful"
	turncScope     = "turnc"
	// ~60s при PermissionRefreshInterval=30s, внутри 5-мин lifetime permission.
	permFailThreshold = 2
)

// permWatchFactory: для scope "turnc" возвращает logger, который зовёт onDead
// после permFailThreshold проваленных циклов refresh подряд.
type permWatchFactory struct {
	inner     logging.LoggerFactory
	onDead    func()
	threshold int
}

func (f *permWatchFactory) NewLogger(scope string) logging.LeveledLogger {
	inner := f.inner.NewLogger(scope)
	if scope != turncScope {
		return inner
	}
	return &permWatchLogger{LeveledLogger: inner, f: f}
}

type permWatchLogger struct {
	logging.LeveledLogger
	f     *permWatchFactory
	mu    sync.Mutex
	fails int
	fired bool
}

// Маркеры — литералы в format pion, матчим format до подстановки args.
func (l *permWatchLogger) note(msg string) {
	switch {
	case strings.Contains(msg, permFailMarker):
		l.mu.Lock()
		l.fails++
		fire := !l.fired && l.fails >= l.f.threshold
		if fire {
			l.fired = true
		}
		l.mu.Unlock()
		if fire && l.f.onDead != nil {
			l.f.onDead()
		}
	case strings.Contains(msg, permOKMarker):
		l.mu.Lock()
		l.fails = 0
		l.mu.Unlock()
	}
}

func (l *permWatchLogger) Warn(msg string) {
	l.note(msg)
	l.LeveledLogger.Warn(msg)
}

func (l *permWatchLogger) Warnf(format string, args ...any) {
	l.note(format)
	l.LeveledLogger.Warnf(format, args...)
}

func (l *permWatchLogger) Debug(msg string) {
	l.note(msg)
	l.LeveledLogger.Debug(msg)
}

func (l *permWatchLogger) Debugf(format string, args ...any) {
	l.note(format)
	l.LeveledLogger.Debugf(format, args...)
}
