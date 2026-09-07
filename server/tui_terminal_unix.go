//go:build linux || darwin || freebsd || netbsd || openbsd || dragonfly

package main

import (
	"os"

	"golang.org/x/sys/unix"
)

func enableTUIInputMode() func() {
	if !isInteractiveStdin() {
		return nil
	}
	fd := int(os.Stdin.Fd())
	termios, err := unix.IoctlGetTermios(fd, termiosGet)
	if err != nil {
		return nil
	}
	original := *termios
	termios.Lflag &^= unix.ICANON | unix.ECHO
	termios.Cc[unix.VMIN] = 1
	termios.Cc[unix.VTIME] = 0
	if err := unix.IoctlSetTermios(fd, termiosSet, termios); err != nil {
		return nil
	}
	return func() {
		_ = unix.IoctlSetTermios(fd, termiosSet, &original)
	}
}

func isInteractiveStdin() bool {
	info, err := os.Stdin.Stat()
	if err != nil {
		return false
	}
	return (info.Mode() & os.ModeCharDevice) != 0
}
