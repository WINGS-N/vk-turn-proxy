//go:build linux

package udpoffload

import (
	"encoding/binary"
	"net"

	"golang.org/x/sys/unix"
)

// enableGRO просит ядро склеивать серию датаграмм одного потока в одно чтение
func enableGRO(udp *net.UDPConn) bool {
	raw, err := udp.SyscallConn()
	if err != nil {
		return false
	}
	var setErr error
	if ctlErr := raw.Control(func(fd uintptr) {
		setErr = unix.SetsockoptInt(int(fd), unix.IPPROTO_UDP, unix.UDP_GRO, 1)
	}); ctlErr != nil || setErr != nil {
		return false
	}
	return true
}

// segmentSize достаёт из управляющих сообщений размер, которым ядро склеило.
// Размера нет - значит чтение принесло ровно одну датаграмму
func segmentSize(control []byte) int {
	messages, err := unix.ParseSocketControlMessage(control)
	if err != nil {
		return 0
	}
	for _, message := range messages {
		if message.Header.Level != unix.IPPROTO_UDP || message.Header.Type != unix.UDP_GRO {
			continue
		}
		if len(message.Data) < 2 {
			continue
		}
		// Ядро пишет размер в своём порядке байтов
		return int(binary.NativeEndian.Uint16(message.Data))
	}
	return 0
}
