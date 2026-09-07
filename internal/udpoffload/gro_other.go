//go:build !linux

package udpoffload

import "net"

// Разгрузка UDP живёт только в ядре Linux, у остальных её нет вовсе, поэтому
// там читаем по датаграмме за раз и не тащим в сборку пакет unix
func enableGRO(*net.UDPConn) bool { return false }

func segmentSize([]byte) int { return 0 }
