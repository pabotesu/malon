// Package manager implements the MALON Transport Manager.
//
// The Transport Manager is the central coordinator:
//   - Holds a registry of peer.Peer references (received from mion at startup).
//   - Owns per-relay InternalProxy instances and their HTTP/2 CONNECT streams.
//   - Dispatches CONTROL envelopes to path state updates.
//   - Calls peer.Peer.SetConn to switch between Relay-H2 and Direct-H3 paths.
package manager

import (
	"context"
	"crypto/ed25519"
	"fmt"
	"log/slog"
	"sync"

	"github.com/pabotesu/malon/internal/auth"
	"github.com/pabotesu/malon/internal/h2proxy"
	"github.com/pabotesu/malon/internal/identity"
	mionpkg "github.com/pabotesu/mion/mion"
	"github.com/pabotesu/mion/peer"
)

// peerEntry holds a mion peer and the relay URL used to reach it (empty for
// proxy-role peers that are reached directly, not through a relay).
type peerEntry struct {
	peer     *peer.Peer
	relayURL string
}

// Manager coordinates transport paths for all known peers.
type Manager struct {
	selfID   identity.PeerID
	selfPriv ed25519.PrivateKey
	insecure bool // skip relay TLS cert verification (testing only)

	mu    sync.RWMutex
	peers map[identity.PeerID]*peerEntry // malon PeerID → peer + relay URL

	// proxies is a pool of InternalProxy instances keyed by relay URL.
	// Created lazily in RegisterPeer; a single relay URL maps to one proxy.
	proxyMu sync.Mutex
	proxies map[string]*h2proxy.InternalProxy

	controlCh chan h2proxy.ControlMessage
	acceptCh  chan *h2proxy.EnvelopeNetConn

	mion *mionpkg.Mion
	ctx  context.Context // set when Run is called
}

// New creates a Manager.
//
//   - selfPriv: local Ed25519 private key (used to derive selfID and for inner mTLS).
//   - tlsInsecure: skip TLS certificate verification on the relay connection (testing only).
//   - m: the Mion instance; used to activate TUN forwarding after SetConn.
func New(selfPriv ed25519.PrivateKey, tlsInsecure bool, m *mionpkg.Mion) *Manager {
	pub := selfPriv.Public().(ed25519.PublicKey)
	selfID := identity.PeerIDFromPublicKey(pub)

	controlCh := make(chan h2proxy.ControlMessage, 64)
	acceptCh := make(chan *h2proxy.EnvelopeNetConn, 16)

	return &Manager{
		selfID:    selfID,
		selfPriv:  selfPriv,
		insecure:  tlsInsecure,
		peers:     make(map[identity.PeerID]*peerEntry),
		proxies:   make(map[string]*h2proxy.InternalProxy),
		controlCh: controlCh,
		acceptCh:  acceptCh,
		mion:      m,
	}
}

// getOrCreateProxy returns the InternalProxy for the given relay URL,
// creating one if it doesn't exist yet.
func (m *Manager) getOrCreateProxy(relayURL string) *h2proxy.InternalProxy {
	m.proxyMu.Lock()
	defer m.proxyMu.Unlock()
	if p, ok := m.proxies[relayURL]; ok {
		return p
	}
	p := h2proxy.NewProxy(m.selfID, relayURL, m.controlCh, m.acceptCh, m.insecure)
	m.proxies[relayURL] = p
	return p
}

// RegisterPeer registers a mion peer.Peer with MALON.
//   - pub: the peer's Ed25519 public key.
//   - p: the mion peer object.
//   - relayURL: the relay endpoint used to reach this peer (empty for proxy-role nodes).
//
// Must be called before Run.
func (m *Manager) RegisterPeer(pub ed25519.PublicKey, p *peer.Peer, relayURL string) error {
	id := identity.PeerIDFromPublicKey(pub)
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, exists := m.peers[id]; exists {
		return fmt.Errorf("manager: peer %s already registered", id)
	}
	m.peers[id] = &peerEntry{peer: p, relayURL: relayURL}
	// Pre-create the proxy so it is available before Run.
	if relayURL != "" {
		m.getOrCreateProxy(relayURL)
	}
	slog.Info("manager: peer registered", "peer_id", id)
	return nil
}

// Run connects to all relay proxies and starts dispatching loops.
// Each relay connection runs independently; a failure in one relay does not
// affect peers on other relays. Blocks until ctx is cancelled.
func (m *Manager) Run(ctx context.Context) error {
	m.ctx = ctx
	go m.acceptLoop(ctx)
	go m.controlLoop(ctx)
	go m.autoConnectLoop(ctx)

	m.proxyMu.Lock()
	type proxyWithURL struct {
		url string
		p   *h2proxy.InternalProxy
	}
	var entries []proxyWithURL
	for url, p := range m.proxies {
		entries = append(entries, proxyWithURL{url: url, p: p})
	}
	m.proxyMu.Unlock()

	if len(entries) == 0 {
		// Proxy-role: no outbound relay connections; just wait for context.
		<-ctx.Done()
		return nil
	}

	// Each relay connection is independent. A failure is logged but does not
	// terminate connections to other relays.
	var wg sync.WaitGroup
	for _, e := range entries {
		e := e
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := e.p.Connect(ctx); err != nil && ctx.Err() == nil {
				slog.Error("manager: relay connection closed", "relay", e.url, "err", err)
			}
		}()
	}
	wg.Wait()
	return nil
}

// autoConnectLoop waits for each relay proxy to become ready, then initiates
// outbound sessions to all peers that use that relay.
func (m *Manager) autoConnectLoop(ctx context.Context) {
	m.proxyMu.Lock()
	proxies := make(map[string]*h2proxy.InternalProxy, len(m.proxies))
	for url, p := range m.proxies {
		proxies[url] = p
	}
	m.proxyMu.Unlock()

	var wg sync.WaitGroup
	for relayURL, proxy := range proxies {
		relayURL, proxy := relayURL, proxy
		wg.Add(1)
		go func() {
			defer wg.Done()
			select {
			case <-ctx.Done():
				return
			case <-proxy.Connected():
			}
			m.mu.RLock()
			var ids []identity.PeerID
			for id, entry := range m.peers {
				if entry.relayURL == relayURL {
					ids = append(ids, id)
				}
			}
			m.mu.RUnlock()
			for _, id := range ids {
				if err := m.ConnectPeer(id); err != nil {
					slog.Warn("manager: auto-connect failed", "peer_id", id, "err", err)
				}
			}
		}()
	}
	wg.Wait()
}

// ConnectPeer opens a Relay-H2 session to peerID, performs inner mTLS
// as the client side, and calls SetConn on the corresponding mion peer.Peer.
func (m *Manager) ConnectPeer(peerID identity.PeerID) error {
	m.mu.RLock()
	entry, ok := m.peers[peerID]
	m.mu.RUnlock()
	if !ok {
		return fmt.Errorf("manager: unknown peer %s", peerID)
	}
	if entry.relayURL == "" {
		return fmt.Errorf("manager: peer %s has no relay URL configured", peerID)
	}

	proxy := m.getOrCreateProxy(entry.relayURL)
	envConn := proxy.NewSession(peerID)

	// Inner mTLS: this node is the TLS client (outbound connection).
	tlsCfg, err := auth.NewClientTLSConfig(m.selfPriv, m.knownPeerSet())
	if err != nil {
		envConn.Close()
		return fmt.Errorf("manager: build client TLS config: %w", err)
	}
	relayConn, err := h2proxy.NewRelayTunnelConnWithMTLS(envConn, tlsCfg, true)
	if err != nil {
		envConn.Close()
		return fmt.Errorf("manager: inner mTLS handshake (client): %w", err)
	}

	entry.peer.SetConn(relayConn)
	if m.mion != nil && m.ctx != nil {
		m.mion.StartForwardConnToTUN(m.ctx, entry.peer)
	}
	go m.controlReadLoop(peerID, relayConn)
	slog.Info("manager: relay tunnel established (inner mTLS)", "peer_id", peerID)
	return nil
}

// acceptLoop handles incoming EnvelopeNetConns (initiated by remote peers).
func (m *Manager) acceptLoop(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case envConn, ok := <-m.acceptCh:
			if !ok {
				return
			}
			go m.handleIncoming(envConn)
		}
	}
}

// handleIncoming sets up a RelayTunnelConn for a remotely-initiated session,
// performing inner mTLS as the TLS server side.
func (m *Manager) handleIncoming(envConn *h2proxy.EnvelopeNetConn) {
	peerID := envConn.PeerID()

	m.mu.RLock()
	entry, ok := m.peers[peerID]
	m.mu.RUnlock()
	if !ok {
		slog.Warn("manager: incoming session from unknown peer, closing", "peer_id", peerID)
		envConn.Close()
		return
	}

	// Inner mTLS: this node is the TLS server (inbound connection).
	tlsCfg, err := auth.NewServerTLSConfig(m.selfPriv, m.knownPeerSet())
	if err != nil {
		slog.Error("manager: build server TLS config", "peer_id", peerID, "err", err)
		envConn.Close()
		return
	}
	relayConn, err := h2proxy.NewRelayTunnelConnWithMTLS(envConn, tlsCfg, false)
	if err != nil {
		slog.Error("manager: inner mTLS handshake (server)", "peer_id", peerID, "err", err)
		envConn.Close()
		return
	}

	entry.peer.SetConn(relayConn)
	if m.mion != nil && m.ctx != nil {
		m.mion.StartForwardConnToTUN(m.ctx, entry.peer)
	}
	go m.controlReadLoop(peerID, relayConn)
	slog.Info("manager: incoming relay tunnel accepted (inner mTLS)", "peer_id", peerID)
}

// controlReadLoop reads CONTROL frames from a per-peer RelayTunnelConn and
// dispatches them to handleControl. Runs as a goroutine until the conn closes.
func (m *Manager) controlReadLoop(peerID identity.PeerID, rc *h2proxy.RelayTunnelConn) {
	for {
		payload, err := rc.ReadControl()
		if err != nil {
			slog.Debug("manager: control read loop ended", "peer_id", peerID, "err", err)
			return
		}
		m.handleControl(h2proxy.ControlMessage{SrcPeerID: peerID, Payload: payload})
	}
}

// controlLoop is retained for backward compatibility but is no longer the
// primary path for CONTROL delivery (superseded by per-peer controlReadLoop).
func (m *Manager) controlLoop(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case msg, ok := <-m.controlCh:
			if !ok {
				return
			}
			m.handleControl(msg)
		}
	}
}

func (m *Manager) handleControl(msg h2proxy.ControlMessage) {
	// M4 以降で candidate / PathState の処理を追加する。
	slog.Debug("manager: control message received", "src", msg.SrcPeerID, "len", len(msg.Payload))
}

// knownPeerSet returns a snapshot of registered peer IDs for use in TLS
// certificate verification.
func (m *Manager) knownPeerSet() map[identity.PeerID]struct{} {
	m.mu.RLock()
	defer m.mu.RUnlock()
	set := make(map[identity.PeerID]struct{}, len(m.peers))
	for id := range m.peers {
		set[id] = struct{}{}
	}
	return set
}
