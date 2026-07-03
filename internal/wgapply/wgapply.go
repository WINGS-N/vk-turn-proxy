// Package wgapply configures a live WireGuard interface for the vk-turn-proxy
// node: it brings up the tunnel device and adds/removes the peers the peerstore
// tracks. It uses wgctrl (netlink, pure Go) to talk to the kernel WireGuard
// module. AmneziaWG uses the same peer model over a userspace backend; that
// applier can plug in behind the same interface later.
package wgapply

import (
	"fmt"
	"net"
	"os/exec"

	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// Peer is a tunnel client to program onto the interface.
type Peer struct {
	PublicKey  string
	AllowedIPs string
}

// Applier programs the tunnel interface. Implementations must be safe for
// concurrent use by the peerstore.
type Applier interface {
	EnsureInterface(name, privateKeyB64 string, listenPort int, address string) error
	SetPeer(name string, peer Peer) error
	RemovePeer(name, publicKeyB64 string) error
	Close() error
}

// Noop tracks nothing on the host; used when host apply is disabled so peers
// live in memory only (and in unit tests).
type Noop struct{}

func (Noop) EnsureInterface(string, string, int, string) error { return nil }
func (Noop) SetPeer(string, Peer) error                        { return nil }
func (Noop) RemovePeer(string, string) error                   { return nil }
func (Noop) Close() error                                      { return nil }

// WGCtrl applies peers onto a kernel WireGuard interface via netlink.
type WGCtrl struct {
	client *wgctrl.Client
}

// NewWGCtrl opens a wgctrl client. It requires CAP_NET_ADMIN (root).
func NewWGCtrl() (*WGCtrl, error) {
	client, err := wgctrl.New()
	if err != nil {
		return nil, fmt.Errorf("wgapply: open wgctrl: %w", err)
	}
	return &WGCtrl{client: client}, nil
}

// EnsureInterface creates the interface if missing, assigns its address, brings
// it up, and sets its private key and listen port.
func (w *WGCtrl) EnsureInterface(name, privateKeyB64 string, listenPort int, address string) error {
	if _, err := w.client.Device(name); err != nil {
		if err := createWireguardLink(name, address); err != nil {
			return err
		}
	}
	key, err := wgtypes.ParseKey(privateKeyB64)
	if err != nil {
		return fmt.Errorf("wgapply: parse private key: %w", err)
	}
	port := listenPort
	return w.client.ConfigureDevice(name, wgtypes.Config{
		PrivateKey: &key,
		ListenPort: &port,
	})
}

// SetPeer adds or updates a peer on the interface.
func (w *WGCtrl) SetPeer(name string, peer Peer) error {
	cfg, err := peerConfig(peer, false)
	if err != nil {
		return err
	}
	return w.client.ConfigureDevice(name, wgtypes.Config{Peers: []wgtypes.PeerConfig{cfg}})
}

// RemovePeer deletes a peer from the interface.
func (w *WGCtrl) RemovePeer(name, publicKeyB64 string) error {
	pub, err := wgtypes.ParseKey(publicKeyB64)
	if err != nil {
		return fmt.Errorf("wgapply: parse public key: %w", err)
	}
	return w.client.ConfigureDevice(name, wgtypes.Config{Peers: []wgtypes.PeerConfig{{
		PublicKey: pub,
		Remove:    true,
	}}})
}

func (w *WGCtrl) Close() error { return w.client.Close() }

// peerConfig translates a Peer into a wgtypes.PeerConfig. It is the part worth
// unit-testing without a live device.
func peerConfig(peer Peer, remove bool) (wgtypes.PeerConfig, error) {
	pub, err := wgtypes.ParseKey(peer.PublicKey)
	if err != nil {
		return wgtypes.PeerConfig{}, fmt.Errorf("wgapply: parse public key: %w", err)
	}
	_, ipnet, err := net.ParseCIDR(peer.AllowedIPs)
	if err != nil {
		return wgtypes.PeerConfig{}, fmt.Errorf("wgapply: parse allowed ips %q: %w", peer.AllowedIPs, err)
	}
	return wgtypes.PeerConfig{
		PublicKey:         pub,
		Remove:            remove,
		ReplaceAllowedIPs: true,
		AllowedIPs:        []net.IPNet{*ipnet},
	}, nil
}

func createWireguardLink(name, address string) error {
	if err := runIP("link", "add", name, "type", "wireguard"); err != nil {
		return err
	}
	if address != "" {
		if err := runIP("addr", "add", address, "dev", name); err != nil {
			return err
		}
	}
	return runIP("link", "set", name, "up")
}

func runIP(args ...string) error {
	out, err := exec.Command("ip", args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("wgapply: ip %v: %w (%s)", args, err, out)
	}
	return nil
}
