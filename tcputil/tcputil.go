package tcputil

import (
	"net"
	"time"

	"github.com/xtaci/kcp-go/v5"
	"github.com/xtaci/smux"
)

// DtlsPacketConn wraps a DTLS net.Conn as a PacketConn for KCP.
type DtlsPacketConn struct {
	conn net.Conn
}

func NewDtlsPacketConn(conn net.Conn) *DtlsPacketConn {
	return &DtlsPacketConn{conn: conn}
}

func (d *DtlsPacketConn) ReadFrom(buffer []byte) (int, net.Addr, error) {
	readBytes, err := d.conn.Read(buffer)
	return readBytes, d.conn.RemoteAddr(), err
}

func (d *DtlsPacketConn) WriteTo(buffer []byte, _ net.Addr) (int, error) {
	return d.conn.Write(buffer)
}

func (d *DtlsPacketConn) Close() error {
	return d.conn.Close()
}

func (d *DtlsPacketConn) LocalAddr() net.Addr {
	return d.conn.LocalAddr()
}

func (d *DtlsPacketConn) SetDeadline(deadline time.Time) error {
	return d.conn.SetDeadline(deadline)
}

func (d *DtlsPacketConn) SetReadDeadline(deadline time.Time) error {
	return d.conn.SetReadDeadline(deadline)
}

func (d *DtlsPacketConn) SetWriteDeadline(deadline time.Time) error {
	return d.conn.SetWriteDeadline(deadline)
}

func NewKCPOverDTLS(dtlsConn net.Conn, isServer bool) (*kcp.UDPSession, error) {
	packetConn := NewDtlsPacketConn(dtlsConn)

	block, err := kcp.NewNoneBlockCrypt(nil)
	if err != nil {
		return nil, err
	}

	var session *kcp.UDPSession
	if isServer {
		listener, err := kcp.ServeConn(block, 0, 0, packetConn)
		if err != nil {
			return nil, err
		}
		if err = listener.SetDeadline(time.Now().Add(30 * time.Second)); err != nil {
			return nil, err
		}
		session, err = listener.AcceptKCP()
		if err != nil {
			return nil, err
		}
	} else {
		session, err = kcp.NewConn2(dtlsConn.RemoteAddr(), block, 0, 0, packetConn)
		if err != nil {
			return nil, err
		}
	}

	session.SetNoDelay(1, 20, 2, 1)
	session.SetWindowSize(256, 256)
	session.SetMtu(1200)
	session.SetACKNoDelay(true)

	return session, nil
}

func DefaultSmuxConfig() *smux.Config {
	config := smux.DefaultConfig()
	config.MaxReceiveBuffer = 4 * 1024 * 1024
	config.MaxStreamBuffer = 1 * 1024 * 1024
	config.KeepAliveInterval = 10 * time.Second
	config.KeepAliveTimeout = 30 * time.Second
	return config
}
