package peerstore

import (
	"testing"

	"github.com/cacggghp/vk-turn-proxy/internal/wgapply"
)

type fakeApplier struct {
	set     []wgapply.Peer
	removed []string
	stats   map[string]wgapply.Counters
}

func (f *fakeApplier) EnsureInterface(string, string, int, string) error { return nil }
func (f *fakeApplier) SetPeer(_ string, p wgapply.Peer) error            { f.set = append(f.set, p); return nil }
func (f *fakeApplier) RemovePeer(_ string, pub string) error {
	f.removed = append(f.removed, pub)
	return nil
}
func (f *fakeApplier) PeerStats(string) (map[string]wgapply.Counters, error) { return f.stats, nil }
func (f *fakeApplier) Close() error                                          { return nil }

func TestPeerstoreProgramsInterface(t *testing.T) {
	fa := &fakeApplier{}
	s, err := New("10.66.66.0/24", "wg0", "", fa)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	created, err := s.Create("", "")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if len(fa.set) != 1 {
		t.Fatalf("applier SetPeer calls = %d, want 1", len(fa.set))
	}
	if fa.set[0].PublicKey != created.Peer.PublicKey || fa.set[0].AllowedIPs != "10.66.66.2/32" {
		t.Fatalf("applied peer wrong: %+v", fa.set[0])
	}

	if !s.Delete(created.Peer.PublicKey) {
		t.Fatal("Delete returned false")
	}
	if len(fa.removed) != 1 || fa.removed[0] != created.Peer.PublicKey {
		t.Fatalf("applier RemovePeer = %v", fa.removed)
	}
}

func TestPeerstoreIdempotentDoesNotReapply(t *testing.T) {
	fa := &fakeApplier{}
	s, _ := New("10.66.66.0/24", "wg0", "", fa)
	c, _ := s.Create("pubkey", "")
	if _, err := s.Create("pubkey", ""); err != nil {
		t.Fatalf("Create again: %v", err)
	}
	if len(fa.set) != 1 {
		t.Fatalf("re-creating an existing peer re-applied it: %d calls", len(fa.set))
	}
	_ = c
}

// Счётчики пира приходят из ядра при чтении списка: своей бухгалтерии у релея
// нет, и без этого расписки клиента не с чем сверять
func TestListCarriesKernelCounters(t *testing.T) {
	fa := &fakeApplier{}
	store, err := New("10.66.66.0/24", "wg-test", "", fa)
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	created, err := store.Create("", "")
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	fa.stats = map[string]wgapply.Counters{created.Peer.PublicKey: {Up: 4096, Down: 8192}}

	peers := store.List()
	if len(peers) != 1 {
		t.Fatalf("не тот список: %+v", peers)
	}
	if peers[0].RxBytes != 4096 || peers[0].TxBytes != 8192 {
		t.Fatalf("счётчики ядра проебались: rx=%d tx=%d", peers[0].RxBytes, peers[0].TxBytes)
	}
}
