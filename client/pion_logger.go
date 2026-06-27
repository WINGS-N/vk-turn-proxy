package main

import (
	"strings"

	"github.com/pion/logging"
)

// newTurnLoggerFactory wraps pion's default logger and drops the benign TURN
// "refresh permissions" failures. The OK TURN server rejects pion's periodic
// CreatePermission refresh with a 400, but media keeps flowing over the bound
// channel and our per-stream recycle reinstalls a fresh allocation/permission
// before it lapses, so the error is pure noise that otherwise floods the log.
func newTurnLoggerFactory() logging.LoggerFactory {
	return turnLoggerFactory{inner: logging.NewDefaultLoggerFactory()}
}

type turnLoggerFactory struct {
	inner logging.LoggerFactory
}

func (f turnLoggerFactory) NewLogger(scope string) logging.LeveledLogger {
	return &turnLogger{LeveledLogger: f.inner.NewLogger(scope)}
}

type turnLogger struct {
	logging.LeveledLogger
}

func (l *turnLogger) Errorf(format string, args ...interface{}) {
	if strings.Contains(format, "refresh permissions") {
		return
	}
	l.LeveledLogger.Errorf(format, args...)
}

func (l *turnLogger) Warnf(format string, args ...interface{}) {
	if strings.Contains(format, "refresh permissions") {
		return
	}
	l.LeveledLogger.Warnf(format, args...)
}
