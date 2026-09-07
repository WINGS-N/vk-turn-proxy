//go:build linux

package main

import "golang.org/x/sys/unix"

// Запрос termios у ioctl зовётся по-разному на каждом ядре, поэтому имя живёт
// рядом с платформой, а не в общем коде
const (
	termiosGet = unix.TCGETS
	termiosSet = unix.TCSETS
)
