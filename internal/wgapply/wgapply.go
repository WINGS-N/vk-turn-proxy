// Package wgapply configures a live WireGuard interface for the vk-turn-proxy
// node: it brings up the tunnel device and adds/removes the peers the peerstore
// tracks. It uses wgctrl (netlink, pure Go) to talk to the kernel WireGuard
// module. AmneziaWG uses the same peer model over a userspace backend; that
// applier can plug in behind the same interface later.
package wgapply

import (
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"strings"

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
	// PeerStats отдаёт счётчики ядра по каждому пиру. Ядро считает
	// расшифрованные датаграммы, то есть ровно то же, что клиент подписывает в
	// расписке: обёртка DTLS и SRTP сюда не попадает
	PeerStats(name string) (map[string]Counters, error)
	Close() error
}

// Counters - что ядро насчитало по пиру. Направление от лица КЛИЕНТА: Up это
// то, что он отправил, Down - то, что получил
type Counters struct {
	Up   uint64
	Down uint64
}

// Noop tracks nothing on the host; used when host apply is disabled so peers
// live in memory only (and in unit tests).
type Noop struct{}

func (Noop) EnsureInterface(string, string, int, string) error { return nil }
func (Noop) SetPeer(string, Peer) error                        { return nil }
func (Noop) RemovePeer(string, string) error                   { return nil }
func (Noop) PeerStats(string) (map[string]Counters, error)     { return nil, nil }
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
	// Bringing the device up is only half a working tunnel: without forwarding and
	// egress NAT the peers get an interface that routes nowhere. Doing it here keeps
	// wg-apply a single switch instead of a switch plus a page of host setup.
	if err := ensureForwarding(); err != nil {
		log.Printf("wgapply: %s", err)
	}
	if err := ensureForwardAccept(name); err != nil {
		log.Printf("wgapply: %s", err)
	}
	if err := ensureEgressNAT(name, address); err != nil {
		log.Printf("wgapply: %s", err)
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

// PeerStats снимает счётчики с живого интерфейса
func (w *WGCtrl) PeerStats(name string) (map[string]Counters, error) {
	device, err := w.client.Device(name)
	if err != nil {
		return nil, fmt.Errorf("wgapply: read %s: %w", name, err)
	}
	out := make(map[string]Counters, len(device.Peers))
	for _, peer := range device.Peers {
		// ReceiveBytes у ядра это принятое ОТ пира, то есть отправленное
		// клиентом, и наоборот
		out[peer.PublicKey.String()] = Counters{
			Up:   uint64(peer.ReceiveBytes),
			Down: uint64(peer.TransmitBytes),
		}
	}
	return out, nil
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
		// A distro kernel ships wireguard as a module that nothing has loaded yet,
		// and "ip link add type wireguard" is usually the first thing on the box to
		// ask for it. Load it and retry once rather than making every operator run
		// modprobe by hand before the relay will start.
		if modErr := loadWireguardModule(); modErr != nil {
			return fmt.Errorf("%w (loading the wireguard module also failed: %s)", err, modErr)
		}
		if retryErr := runIP("link", "add", name, "type", "wireguard"); retryErr != nil {
			return retryErr
		}
	}
	if address != "" {
		if err := runIP("addr", "add", address, "dev", name); err != nil {
			return err
		}
	}
	return runIP("link", "set", name, "up")
}

// loadWireguardModule asks the kernel for the wireguard module. It is a no-op
// when the module is already loaded or built into the kernel, and needs root.
func loadWireguardModule() error {
	if _, err := os.Stat("/sys/module/wireguard"); err == nil {
		return nil
	}
	out, err := exec.Command("modprobe", "wireguard").CombinedOutput()
	if err != nil {
		return fmt.Errorf("modprobe wireguard: %w (%s)", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// ensureForwarding turns on IPv4 forwarding, without which the kernel drops every
// packet arriving on the tunnel that is destined elsewhere.
func ensureForwarding() error {
	const path = "/proc/sys/net/ipv4/ip_forward"
	cur, err := os.ReadFile(path)
	if err == nil && strings.TrimSpace(string(cur)) == "1" {
		return nil
	}
	if err := os.WriteFile(path, []byte("1\n"), 0o644); err != nil {
		return fmt.Errorf("enable ip_forward: %w", err)
	}
	log.Printf("wgapply: enabled net.ipv4.ip_forward")
	return nil
}

// ensureForwardAccept lets the tunnel's traffic through the FORWARD chain.
//
// NAT alone is not enough and the gap is silent: docker sets the FORWARD policy to
// DROP on every host it runs on, so a decrypted packet dies there before POSTROUTING
// is ever consulted. The symptom is a healthy WireGuard peer - handshake fine, bytes
// received climbing - that sends almost nothing back. The rules are inserted at the
// top so a DROP sitting in front of them cannot win, and only when absent, so a
// restart does not stack duplicates.
func ensureForwardAccept(iface string) error {
	added := false
	for _, direction := range []string{"-i", "-o"} {
		rule := []string{"FORWARD", direction, iface, "-j", "ACCEPT"}
		if err := exec.Command("iptables", append([]string{"-C"}, rule...)...).Run(); err == nil {
			continue
		}
		args := append([]string{"-I"}, rule...)
		if out, err := exec.Command("iptables", args...).CombinedOutput(); err != nil {
			return fmt.Errorf("allow forwarding %s %s: %w (%s)", direction, iface, err, strings.TrimSpace(string(out)))
		}
		added = true
	}
	if added {
		log.Printf("wgapply: allowed forwarding for %s", iface)
	}
	return nil
}

// ensureEgressNAT masquerades the tunnel subnet out of whatever interface holds
// the default route. tunnelAddress is the interface address in CIDR form, whose
// network is the subnet the peers live in. The rule is added only when an
// equivalent one is not already installed, so restarts do not stack duplicates.
// A host whose operator runs their own NAT keeps working either way: the check
// finds nothing, one rule is added, and it is a no-op alongside theirs.
func ensureEgressNAT(iface, tunnelAddress string) error {
	subnet, err := tunnelSubnet(tunnelAddress)
	if err != nil {
		return err
	}
	// The table selector has to precede the command flag: iptables reads "-C" as
	// taking the chain name next, so "-C -t nat POSTROUTING" is rejected outright.
	rule := func(op string) []string {
		return []string{"-t", "nat", op, "POSTROUTING", "-s", subnet, "!", "-o", iface, "-j", "MASQUERADE"}
	}
	if err := exec.Command("iptables", rule("-C")...).Run(); err == nil {
		return nil
	}
	out, err := exec.Command("iptables", rule("-A")...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("add egress NAT for %s: %w (%s)", subnet, err, strings.TrimSpace(string(out)))
	}
	log.Printf("wgapply: masquerading %s out of the default route", subnet)
	return nil
}

// tunnelSubnet turns an interface address such as 10.66.66.1/24 into the network
// it belongs to, 10.66.66.0/24.
func tunnelSubnet(address string) (string, error) {
	if strings.TrimSpace(address) == "" {
		return "", fmt.Errorf("no tunnel address to derive a subnet from")
	}
	_, ipnet, err := net.ParseCIDR(address)
	if err != nil {
		return "", fmt.Errorf("parse tunnel address %q: %w", address, err)
	}
	return ipnet.String(), nil
}

func runIP(args ...string) error {
	out, err := exec.Command("ip", args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("wgapply: ip %v: %w (%s)", args, err, out)
	}
	return nil
}
