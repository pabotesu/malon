// Package manager implements the MALON Transport Manager.
//
// The Transport Manager is the central coordinator:
//   - Holds a registry of peer.Peer references (received from mion at startup).
//   - Owns InternalProxy and its shared HTTP/2 CONNECT stream to the Relay.
//   - Dispatches CONTROL envelopes to path state updates.
//   - Calls peer.Peer.SetConn to switch between Relay-H2 and Direct-H3 paths.
package manager

import (
	"context"
	"crypto/ed25519"
	"fmt"
	"log/slog"
	"sync"

	"github.com/pabotesu/malon/internal/h2proxy"
	"github.com/pabotesu/malon/internal/identity"
	mionpkg "github.com/pabotesu/mion/mion"
	"github.com/pabotesu/mion/peer"
)

// Manager coordinates transport paths for all known peers.
type Manager struct {
	selfID   identity.PeerID
	selfPriv ed25519.PrivateKey
	relayURL string

	mu    sync.RWMutex
	peers map[identity.PeerID]*peer.Peer // malon PeerID → mion Peer

	proxy     *h2proxy.InternalProxy
	controlCh chan h2proxy.ControlMessage
	acceptCh  chan *h2proxy.EnvelopeNetConn

	mion *mionpkg.Mion
	ctx  context.Context // set when Run is called
}

// New creates a Manager.
//
//   - selfPriv: local Ed25519 private key (used to derive selfID and for inner mTLS).
//   - relayURL: e.g. "https://relay.example.com:443".
//   - m: the Mion instance; used to activate TUN forwarding after SetConn.
func New(selfPriv ed25519.PrivateKey, relayURL string, m *mionpkg.Mion) *Manager {
	pub := selfPriv.Public().(ed25519.PublicKey)
	selfID := identity.PeerIDFromPublicKey(pub)

	controlCh := make(chan h2proxy.ControlMessage, 64)
	acceptCh := make(chan *h2proxy.EnvelopeNetConn, 16)

	proxy := h2proxy.NewProxy(selfID, relayURL, controlCh, acceptCh)

	return &Manager{
		selfID:    selfID,
		selfPriv:  selfPriv,
		relayURL:  relayURL,
		peers:     make(map[identity.PeerID]*peer.Peer),
		proxy:     proxy,
		controlCh: controlCh,
		acceptCh:  acceptCh,
		mion:      m,
	}
}

// RegisterPeer registers a mion peer.Peer with MALON.
// pub is the peer's Ed25519 public key (used to derive its PeerID).
// Must be called before Run.
func (m *Manager) RegisterPeer(pub ed25519.PublicKey, p *peer.Peer) error {
	id := identity.PeerIDFromPublicKey(pub)
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, exists := m.peers[id]; exists {
		return fmt.Errorf("manager: peer %s already registered", id)
	}
	m.peers[id] = p
	slog.Info("manager: peer registered", "peer_id", id)
	return nil
}

// Run connects to the Relay and starts dispatching loops.
// Blocks until ctx is cancelled or a fatal error occurs.
func (m *Manager) Run(ctx context.Context) error {
	m.ctx = ctx
	go m.acceptLoop(ctx)
	go m.controlLoop(ctx)
	go m.autoConnectLoop(ctx)

	// Connect blocks; caller should retry with back-off.
	return m.proxy.Connect(ctx)
}

// autoConnectLoop waits for the relay to become ready, then initiates outbound
// sessions to all registered peers so that TUN→Relay forwarding is active on
// both sides without requiring manual intervention.
func (m *Manager) autoConnectLoop(ctx context.Context) {
	select {
	case <-ctx.Done():
		return
	case <-m.proxy.Connected():
	}

	m.mu.RLock()
	peerIDs := make([]identity.PeerID, 0, len(m.peers))
	for id := range m.peers {
		peerIDs = append(peerIDs, id)
	}
	m.mu.RUnlock()

	for _, id := range peerIDs {
		if err := m.ConnectPeer(id); err != nil {
			slog.Warn("manager: auto-connect failed", "peer_id", id, "err", err)
		}
	}
}

// ConnectPeer opens a Relay-H2 session to peerID and calls SetConn on the
// corresponding mion peer.Peer.
func (m *Manager) ConnectPeer(peerID identity.PeerID) error {
	m.mu.RLock()
	p, ok := m.peers[peerID]
	m.mu.RUnlock()
	if !ok {
		return fmt.Errorf("manager: unknown peer %s", peerID)
	}

	envConn := m.proxy.NewSession(peerID)
	relayConn := h2proxy.NewRelayTunnelConn(envConn)
	p.SetConn(relayConn)
	if m.mion != nil && m.ctx != nil {
		m.mion.StartForwardConnToTUN(m.ctx, p)
	}
	slog.Info("manager: relay tunnel established", "peer_id", peerID)
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

// handleIncoming sets up a RelayTunnelConn for a remotely-initiated session.
// In M3 step 1 (no inner mTLS), the session's peerID is taken from the
// Envelope's src_peer_id (trusted via Relay; replaced by mTLS in step 2).
func (m *Manager) handleIncoming(envConn *h2proxy.EnvelopeNetConn) {
	peerID := envConn.PeerID()

	m.mu.RLock()
	p, ok := m.peers[peerID]
	m.mu.RUnlock()
	if !ok {
		slog.Warn("manager: incoming session from unknown peer, closing", "peer_id", peerID)
		envConn.Close()
		return
	}

	relayConn := h2proxy.NewRelayTunnelConn(envConn)
	p.SetConn(relayConn)
	if m.mion != nil && m.ctx != nil {
		m.mion.StartForwardConnToTUN(m.ctx, p)
	}
	slog.Info("manager: incoming relay tunnel accepted", "peer_id", peerID)
}

// controlLoop receives CONTROL messages from InternalProxy and dispatches them.
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
