//go:build !linux

package main

import (
	"errors"
	"net"
)

var errNoSegmentation = errors.New("udp segmentation offload is linux only")

// Ни у винды, ни у макоси UDP_SEGMENT нет, поэтому там пишем по датаграмме за
// раз, а пакет unix в сборку не тащим вовсе
func segmentationAvailable() bool { return false }

func setUDPSegment(*net.UDPConn, int) error { return errNoSegmentation }
