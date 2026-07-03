// Package peerstore tracks the WireGuard/AmneziaWG peers a vk-turn-proxy node
// serves. Both the panel gRPC management API and the app self-enroll path write
// through it, so it is the single source of truth for the node's tunnel peers.
// This first cut keeps peers in memory and allocates keys and addresses; wiring
// the entries onto a live wg interface is a separate step.
package peerstore

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"net/netip"
	"sync"
	"time"
)

// Peer is one tunnel client.
type Peer struct {
	PublicKey   string
	AllowedIPs  string
	RxBytes     uint64
	TxBytes     uint64
	CreatedUnix int64
}

// Store holds a node's peers plus its own server keypair and address pool.
type Store struct {
	mu         sync.Mutex
	iface      string
	prefix     netip.Prefix
	nextHost   uint8
	serverPub  string
	serverPriv string
	peers      map[string]*Peer
	nowUnix    func() int64
}

// New creates a store for the given tunnel CIDR (for example 10.66.66.0/24) and
// interface name, generating a fresh server keypair.
func New(cidr, iface string) (*Store, error) {
	prefix, err := netip.ParsePrefix(cidr)
	if err != nil {
		return nil, fmt.Errorf("peerstore: parse cidr: %w", err)
	}
	if !prefix.Addr().Is4() {
		return nil, errors.New("peerstore: only IPv4 tunnel CIDRs are supported")
	}
	priv, pub, err := generateKeypair()
	if err != nil {
		return nil, err
	}
	return &Store{
		iface:      iface,
		prefix:     prefix.Masked(),
		nextHost:   2,
		serverPub:  pub,
		serverPriv: priv,
		peers:      make(map[string]*Peer),
		nowUnix:    func() int64 { return time.Now().Unix() },
	}, nil
}

// ServerPublicKey returns the node's WireGuard public key (base64).
func (s *Store) ServerPublicKey() string { return s.serverPub }

// Interface returns the tunnel interface name.
func (s *Store) Interface() string { return s.iface }

// Created is the result of Create: the stored peer plus, when the server
// generated the keypair, the private key to hand back to the client once.
type Created struct {
	Peer       Peer
	PrivateKey string
}

// Create adds a peer. An empty publicKey makes the server generate a keypair and
// return the private key. An empty allowedIPs allocates the next free /32 from
// the pool. Creating an already-present public key returns the existing peer,
// which makes app self-enroll idempotent.
func (s *Store) Create(publicKey, allowedIPs string) (Created, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	var generatedPriv string
	if publicKey == "" {
		priv, pub, err := generateKeypair()
		if err != nil {
			return Created{}, err
		}
		publicKey, generatedPriv = pub, priv
	}
	if existing, ok := s.peers[publicKey]; ok {
		return Created{Peer: *existing, PrivateKey: generatedPriv}, nil
	}
	if allowedIPs == "" {
		addr, err := s.allocateLocked()
		if err != nil {
			return Created{}, err
		}
		allowedIPs = addr.String() + "/32"
	}
	peer := &Peer{PublicKey: publicKey, AllowedIPs: allowedIPs, CreatedUnix: s.nowUnix()}
	s.peers[publicKey] = peer
	return Created{Peer: *peer, PrivateKey: generatedPriv}, nil
}

// Delete removes a peer, reporting whether it existed.
func (s *Store) Delete(publicKey string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.peers[publicKey]; !ok {
		return false
	}
	delete(s.peers, publicKey)
	return true
}

// List returns a snapshot of all peers.
func (s *Store) List() []Peer {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]Peer, 0, len(s.peers))
	for _, p := range s.peers {
		out = append(out, *p)
	}
	return out
}

// Count returns the number of peers.
func (s *Store) Count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.peers)
}

func (s *Store) allocateLocked() (netip.Addr, error) {
	base := s.prefix.Addr().As4()
	for s.nextHost < 255 {
		host := s.nextHost
		s.nextHost++
		if host == 0 || host == 1 {
			continue
		}
		b := base
		b[3] = host
		addr := netip.AddrFrom4(b)
		if s.prefix.Contains(addr) {
			return addr, nil
		}
	}
	return netip.Addr{}, errors.New("peerstore: address pool exhausted")
}

func generateKeypair() (privB64, pubB64 string, err error) {
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return "", "", fmt.Errorf("peerstore: generate key: %w", err)
	}
	return base64.StdEncoding.EncodeToString(priv.Bytes()),
		base64.StdEncoding.EncodeToString(priv.PublicKey().Bytes()),
		nil
}
