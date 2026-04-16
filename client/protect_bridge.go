package main

import (
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"syscall"
)

type protectBridge struct {
	conn *net.UnixConn
	mu   sync.Mutex
}

func newProtectBridge(socketName string) (*protectBridge, error) {
	if strings.TrimSpace(socketName) == "" {
		return nil, nil
	}
	addr := socketName
	if !strings.HasPrefix(addr, "@") {
		addr = "@" + addr
	}
	conn, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: addr, Net: "unix"})
	if err != nil {
		return nil, fmt.Errorf("dial protect socket: %w", err)
	}
	return &protectBridge{conn: conn}, nil
}

func (b *protectBridge) Close() error {
	if b == nil || b.conn == nil {
		return nil
	}
	return b.conn.Close()
}

func (b *protectBridge) Control(network, address string, rawConn syscall.RawConn) error {
	if b == nil {
		return nil
	}
	var protectErr error
	err := rawConn.Control(func(fd uintptr) {
		protectErr = b.protectFD(int(fd))
	})
	if err != nil {
		return err
	}
	return protectErr
}

func (b *protectBridge) protectFD(fd int) error {
	if b == nil || b.conn == nil {
		return nil
	}

	b.mu.Lock()
	defer b.mu.Unlock()

	rights := syscall.UnixRights(fd)
	if _, _, err := b.conn.WriteMsgUnix([]byte{1}, rights, nil); err != nil {
		return fmt.Errorf("write protect request: %w", err)
	}

	ack := make([]byte, 1)
	if _, err := io.ReadFull(b.conn, ack); err != nil {
		return fmt.Errorf("read protect response: %w", err)
	}
	if ack[0] != 1 {
		return fmt.Errorf("protect rejected")
	}
	return nil
}
