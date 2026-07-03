package wgapply

import (
	"os"
	"testing"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func TestPeerConfigTranslation(t *testing.T) {
	k, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatalf("gen key: %v", err)
	}
	cfg, err := peerConfig(Peer{PublicKey: k.PublicKey().String(), AllowedIPs: "10.66.66.5/32"}, false)
	if err != nil {
		t.Fatalf("peerConfig: %v", err)
	}
	if cfg.PublicKey.String() != k.PublicKey().String() {
		t.Fatalf("public key mismatch")
	}
	if !cfg.ReplaceAllowedIPs || len(cfg.AllowedIPs) != 1 || cfg.AllowedIPs[0].String() != "10.66.66.5/32" {
		t.Fatalf("allowed ips wrong: %+v", cfg.AllowedIPs)
	}
	if _, err := peerConfig(Peer{PublicKey: k.PublicKey().String(), AllowedIPs: "not-a-cidr"}, false); err == nil {
		t.Fatal("expected an error for a bad allowed-ips value")
	}
}

// TestWGCtrlAppliesPeer programs a peer onto a real kernel WireGuard interface.
// It runs only when WV_WG_TEST_IFACE names an existing wireguard interface
// (a privileged container: `ip link add wg0 type wireguard`). Needs root.
func TestWGCtrlAppliesPeer(t *testing.T) {
	iface := os.Getenv("WV_WG_TEST_IFACE")
	if iface == "" {
		t.Skip("set WV_WG_TEST_IFACE to an existing wireguard interface to run this")
	}
	w, err := NewWGCtrl()
	if err != nil {
		t.Fatalf("NewWGCtrl: %v", err)
	}
	t.Cleanup(func() { _ = w.Close() })

	serverKey, _ := wgtypes.GeneratePrivateKey()
	if err := w.EnsureInterface(iface, serverKey.String(), 51820, ""); err != nil {
		t.Fatalf("EnsureInterface: %v", err)
	}

	peerKey, _ := wgtypes.GeneratePrivateKey()
	pub := peerKey.PublicKey().String()
	if err := w.SetPeer(iface, Peer{PublicKey: pub, AllowedIPs: "10.66.66.2/32"}); err != nil {
		t.Fatalf("SetPeer: %v", err)
	}

	dev, err := w.client.Device(iface)
	if err != nil {
		t.Fatalf("Device: %v", err)
	}
	if dev.ListenPort != 51820 {
		t.Fatalf("listen port = %d, want 51820", dev.ListenPort)
	}
	if !hasPeer(dev.Peers, pub) {
		t.Fatal("peer was not programmed onto the interface")
	}

	if err := w.RemovePeer(iface, pub); err != nil {
		t.Fatalf("RemovePeer: %v", err)
	}
	dev, _ = w.client.Device(iface)
	if hasPeer(dev.Peers, pub) {
		t.Fatal("peer still present after RemovePeer")
	}
}

func hasPeer(peers []wgtypes.Peer, pub string) bool {
	for _, p := range peers {
		if p.PublicKey.String() == pub {
			return true
		}
	}
	return false
}
