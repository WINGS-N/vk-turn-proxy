package main

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"syscall"

	"github.com/pion/transport/v4"
)

type protectedTransportNet struct {
	resolver *protectedResolver
}

func newProtectedTransportNet(resolver *protectedResolver) transport.Net {
	if resolver == nil {
		return newDirectNet()
	}
	return &protectedTransportNet{resolver: resolver}
}

func (n *protectedTransportNet) ListenPacket(network string, address string) (net.PacketConn, error) {
	listenConfig := &net.ListenConfig{}
	if n.resolver != nil && n.resolver.protectBridge != nil {
		listenConfig.Control = n.resolver.protectBridge.Control
	}
	conn, err := listenConfig.ListenPacket(context.Background(), network, address)
	if err == nil {
		tuneUDPBuffers(conn, "protected listen packet")
	}
	return conn, err
}

func (n *protectedTransportNet) ListenUDP(network string, locAddr *net.UDPAddr) (transport.UDPConn, error) {
	conn, err := net.ListenUDP(network, locAddr)
	if err != nil {
		return nil, err
	}
	if err := protectSocket(n.resolver.protectBridge, conn); err != nil {
		_ = conn.Close()
		return nil, err
	}
	tuneUDPBuffers(conn, "protected listen udp")
	return conn, nil
}

func (n *protectedTransportNet) ListenTCP(network string, laddr *net.TCPAddr) (transport.TCPListener, error) {
	listenConfig := &net.ListenConfig{}
	if n.resolver != nil && n.resolver.protectBridge != nil {
		listenConfig.Control = n.resolver.protectBridge.Control
	}
	address := ""
	if laddr != nil {
		address = laddr.String()
	}
	listener, err := listenConfig.Listen(context.Background(), network, address)
	if err != nil {
		return nil, err
	}
	tcpListener, ok := listener.(*net.TCPListener)
	if !ok {
		_ = listener.Close()
		return nil, fmt.Errorf("unexpected TCP listener type: %T", listener)
	}

	return directTCPListener{tcpListener}, nil
}

func (n *protectedTransportNet) Dial(network, address string) (net.Conn, error) {
	return n.resolver.DialContext(context.Background(), network, address)
}

func (n *protectedTransportNet) DialUDP(network string, laddr, raddr *net.UDPAddr) (transport.UDPConn, error) {
	dialer := n.resolver.dialer()
	dialer.LocalAddr = laddr
	conn, err := dialer.DialContext(context.Background(), network, raddr.String())
	if err != nil {
		return nil, err
	}
	udpConn, ok := conn.(*net.UDPConn)
	if !ok {
		_ = conn.Close()
		return nil, fmt.Errorf("unexpected UDP conn type: %T", conn)
	}
	tuneUDPBuffers(udpConn, "protected dial udp")
	return udpConn, nil
}

func (n *protectedTransportNet) DialTCP(network string, laddr, raddr *net.TCPAddr) (transport.TCPConn, error) {
	dialer := n.resolver.dialer()
	dialer.LocalAddr = laddr
	conn, err := dialer.DialContext(context.Background(), network, raddr.String())
	if err != nil {
		return nil, err
	}
	tcpConn, ok := conn.(*net.TCPConn)
	if !ok {
		_ = conn.Close()
		return nil, fmt.Errorf("unexpected TCP conn type: %T", conn)
	}
	return tcpConn, nil
}

func (n *protectedTransportNet) ResolveIPAddr(network, address string) (*net.IPAddr, error) {
	ips, err := n.resolver.LookupIPAddr(context.Background(), address)
	if err != nil {
		return nil, err
	}
	if len(ips) == 0 {
		return nil, fmt.Errorf("no ip addresses for %s", address)
	}
	return &ips[0], nil
}

func (n *protectedTransportNet) ResolveUDPAddr(network, address string) (*net.UDPAddr, error) {
	return n.resolver.ResolveUDPAddr(context.Background(), address)
}

func (n *protectedTransportNet) ResolveTCPAddr(network, address string) (*net.TCPAddr, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	ips, err := n.resolver.LookupIPAddr(context.Background(), host)
	if err != nil {
		return nil, err
	}
	if len(ips) == 0 {
		return nil, fmt.Errorf("no ip addresses for %s", host)
	}
	return &net.TCPAddr{IP: ips[0].IP, Port: mustAtoi(port), Zone: ips[0].Zone}, nil
}

func (n *protectedTransportNet) Interfaces() ([]*transport.Interface, error) {
	return nil, transport.ErrNotSupported
}

func (n *protectedTransportNet) InterfaceByIndex(index int) (*transport.Interface, error) {
	return nil, fmt.Errorf("%w: index=%d", transport.ErrInterfaceNotFound, index)
}

func (n *protectedTransportNet) InterfaceByName(name string) (*transport.Interface, error) {
	return nil, fmt.Errorf("%w: %s", transport.ErrInterfaceNotFound, name)
}

func (n *protectedTransportNet) CreateDialer(dialer *net.Dialer) transport.Dialer {
	if n.resolver != nil && n.resolver.protectBridge != nil {
		dialer.Control = n.resolver.protectBridge.Control
	}
	return directDialer{Dialer: dialer}
}

func (n *protectedTransportNet) CreateListenConfig(listenerConfig *net.ListenConfig) transport.ListenConfig {
	if n.resolver != nil && n.resolver.protectBridge != nil {
		listenerConfig.Control = n.resolver.protectBridge.Control
	}
	return directListenConfig{ListenConfig: listenerConfig}
}

func protectSocket(bridge *protectBridge, conn any) error {
	if bridge == nil || conn == nil {
		return nil
	}
	sysConn, ok := conn.(interface {
		SyscallConn() (syscall.RawConn, error)
	})
	if !ok {
		return nil
	}
	rawConn, err := sysConn.SyscallConn()
	if err != nil {
		return err
	}
	return bridge.Control("", "", rawConn)
}

func mustAtoi(value string) int {
	n, err := strconv.Atoi(value)
	if err != nil {
		return 0
	}
	return n
}
