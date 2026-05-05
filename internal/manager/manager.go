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
	"net/netip"
	"sync"
	"time"

	"github.com/pabotesu/malon/internal/auth"
	"github.com/pabotesu/malon/internal/candidate"
	"github.com/pabotesu/malon/internal/control"
	"github.com/pabotesu/malon/internal/direct"
	"github.com/pabotesu/malon/internal/h2proxy"
	"github.com/pabotesu/malon/internal/h3path"
	"github.com/pabotesu/malon/internal/identity"
	"github.com/pabotesu/malon/internal/stun"
	mionpkg "github.com/pabotesu/mion/mion"
	"github.com/pabotesu/mion/peer"
)

// peerEntry holds a mion peer and the relay URL used to reach it (empty for
// proxy-role peers that are reached directly, not through a relay).
type peerEntry struct {
	peer          *peer.Peer
	relayURL      string
	relayConn     *h2proxy.RelayTunnelConn // current relay conn; used for fallback after direct path breaks
	hasDirectPath bool                     // true while a direct CONNECT-IP path is active
}

// Manager coordinates transport paths for all known peers.
// defaultSTUNServer uses the IPv4-only subdomain provided by Google to avoid
// silent failures on hosts that have IPv6 configured but no working IPv6 route.
// Port 3478 is the standard STUN port (RFC 5389) and is more likely to be
// unblocked on VPS/firewall environments than Google's alternative port 19302.
const defaultSTUNServer = "stun4.l.google.com:3478"

// probeCooldownDur is the minimum interval before retrying a probe to an
// address that previously timed out. Kept short because relay reconnect already
// clears the cooldown map; this only prevents duplicate probes within a single
// relay session (e.g. if candidates are re-sent without a reconnect).
const probeCooldownDur = 30 * time.Second

type Manager struct {
	selfID     identity.PeerID
	selfPriv   ed25519.PrivateKey
	insecure   bool   // skip relay TLS cert verification (testing only)
	stunServer string // STUN server address (host:port)

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

	// Phase 4: DirectH3PathValidator
	validator  *h3path.Validator
	generation uint32 // current network generation (Phase 6 will manage transitions)

	validatedMu sync.RWMutex
	validated   map[identity.PeerID][]*h3path.ValidatedTransport

	// probeCooldown tracks addresses that recently failed probing.
	// Entries are evicted after probeCooldownDur to allow retry on network change.
	probeCooldownMu sync.Mutex
	probeCooldown   map[netip.AddrPort]time.Time

	// Phase 4+: DirectListener for accepting inbound probes.
	directLn      *direct.Listener
	overlayPrefix netip.Prefix // MALON overlay prefix; excluded from embedded candidates
}

// New creates a Manager.
//
//   - selfPriv: local Ed25519 private key (used to derive selfID and for inner mTLS).
//   - interfaceRelayURL: relay this node connects to regardless of peer config (proxy role).
//   - tlsInsecure: skip TLS certificate verification on the relay connection (testing only).
//   - stunServer: STUN server (host:port); empty string uses the default (stun.l.google.com:19302).
//   - overlayPrefix: the MALON overlay prefix (e.g. 100.100.100.0/24); its addresses are
//     excluded from embedded candidates since they are virtual and not reachable directly.
//   - m: the Mion instance; used to activate TUN forwarding after SetConn.
func New(selfPriv ed25519.PrivateKey, interfaceRelayURL string, tlsInsecure bool, stunServer string, overlayPrefix netip.Prefix, m *mionpkg.Mion) *Manager {
	pub := selfPriv.Public().(ed25519.PublicKey)
	selfID := identity.PeerIDFromPublicKey(pub)

	controlCh := make(chan h2proxy.ControlMessage, 64)
	acceptCh := make(chan *h2proxy.EnvelopeNetConn, 16)

	mgr := &Manager{
		selfID:        selfID,
		selfPriv:      selfPriv,
		insecure:      tlsInsecure,
		stunServer:    stunServer,
		peers:         make(map[identity.PeerID]*peerEntry),
		proxies:       make(map[string]*h2proxy.InternalProxy),
		controlCh:     controlCh,
		acceptCh:      acceptCh,
		mion:          m,
		validator:     h3path.New(selfPriv),
		generation:    1,
		validated:     make(map[identity.PeerID][]*h3path.ValidatedTransport),
		probeCooldown: make(map[netip.AddrPort]time.Time),
		overlayPrefix: overlayPrefix,
	}
	// proxy-role: pre-create the relay proxy so Run() can connect to it.
	if interfaceRelayURL != "" {
		mgr.getOrCreateProxy(interfaceRelayURL)
	}
	return mgr
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

	// Start DirectListener for inbound "malon-probe" connections.
	ln, err := direct.New(m.selfPriv, m.knownPeerSet())
	if err != nil {
		slog.Warn("manager: DirectListener failed to start, inbound probes disabled", "err", err)
	} else {
		m.directLn = ln
		slog.Info("manager: DirectListener started", "port", ln.LocalPort())
		go m.probeAcceptLoop(ctx)
	}

	go m.acceptLoop(ctx)
	go m.controlLoop(ctx)

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
		// No relay configured at all; just wait for context.
		<-ctx.Done()
		return nil
	}

	// Each relay runs its own reconnect loop independently.
	var wg sync.WaitGroup
	for _, e := range entries {
		e := e
		wg.Add(1)
		go func() {
			defer wg.Done()
			m.relayConnectLoop(ctx, e.url, e.p)
		}()
	}
	wg.Wait()
	return nil
}

// relayConnectLoop connects to a relay and reconnects with exponential backoff
// after disconnection. On each successful connect, peer sessions are established
// and candidates are exchanged.
func (m *Manager) relayConnectLoop(ctx context.Context, relayURL string, proxy *h2proxy.InternalProxy) {
	backoff := time.Second
	const maxBackoff = 30 * time.Second
	first := true

	for {
		if !first {
			proxy.Reset()
		}
		first = false

		connectDone := make(chan error, 1)
		go func() { connectDone <- proxy.Connect(ctx) }()

		// Wait until connected, connection failed, or context cancelled.
		// Connect() may return an error before connectedCh is ever closed
		// (e.g. when the relay is down), so we must select on both.
		select {
		case <-ctx.Done():
			return
		case err := <-connectDone:
			// Connect returned before signalling connected — relay is down.
			if ctx.Err() != nil {
				return
			}
			slog.Warn("manager: relay connect failed, retrying",
				"relay", relayURL, "err", err, "backoff", backoff)
			select {
			case <-ctx.Done():
				return
			case <-time.After(backoff):
			}
			if backoff < maxBackoff {
				backoff *= 2
			}
			continue
		case <-proxy.Connected():
			// Successfully established CONNECT stream.
		}

		// Connected: bump network generation and clear probe cooldowns so
		// candidates from the new relay session are probed fresh.
		m.mu.Lock()
		m.generation++
		m.mu.Unlock()
		m.probeCooldownMu.Lock()
		m.probeCooldown = make(map[netip.AddrPort]time.Time)
		m.probeCooldownMu.Unlock()
		m.setupRelayPeers(ctx, relayURL)
		backoff = time.Second // reset backoff on success

		// Wait for disconnection.
		select {
		case <-ctx.Done():
			return
		case err := <-connectDone:
			if ctx.Err() != nil {
				return
			}
			slog.Warn("manager: relay disconnected, reconnecting",
				"relay", relayURL, "err", err, "backoff", backoff)
		}

		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff):
		}
		if backoff < maxBackoff {
			backoff *= 2
		}
	}
}

// setupRelayPeers establishes outbound sessions to all peers that use the given
// relay. Called after each successful relay reconnect.
// It resets per-peer direct-path state so probes run immediately with the new
// relay session — without waiting for QUIC keepalive to detect a stale path.
func (m *Manager) setupRelayPeers(ctx context.Context, relayURL string) {
	// Reset direct-path state for all peers on this relay before dialling.
	// The remote peer (e.g. proxy) may have restarted; its QUIC endpoint and
	// DirectListener port may have changed. Clearing hasDirectPath allows
	// validateCandidates to run probes immediately on the new candidates.
	m.mu.Lock()
	var ids []identity.PeerID
	for id, entry := range m.peers {
		if entry.relayURL == relayURL {
			ids = append(ids, id)
			entry.hasDirectPath = false
		}
	}
	m.mu.Unlock()

	for _, id := range ids {
		if ctx.Err() != nil {
			return
		}
		if err := m.ConnectPeer(id); err != nil {
			slog.Warn("manager: peer connect failed after relay reconnect", "peer_id", id, "err", err)
		}
	}
}

// ConnectPeer opens a Relay-H2 session to peerID, performs inner mTLS
// as the client side, and calls SetConn on the corresponding mion peer.Peer.
func (m *Manager) ConnectPeer(peerID identity.PeerID) error {
	return m.connectPeerWithCtx(m.ctx, peerID)
}

// connectPeerWithCtx is the internal implementation of ConnectPeer.
// ctx controls the inner mTLS handshake timeout.
func (m *Manager) connectPeerWithCtx(ctx context.Context, peerID identity.PeerID) error {
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

	// Use a 3s timeout for the inner mTLS handshake so we don't hang
	// indefinitely when the remote peer is not yet connected to the relay.
	// 3s is ample for a local or nearby relay; retryConnectPeer will retry
	// with backoff if it fails, so a shorter timeout converges faster.
	handshakeCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()

	// Inner mTLS: this node is the TLS client (outbound connection).
	tlsCfg, err := auth.NewClientTLSConfig(m.selfPriv, m.knownPeerSet())
	if err != nil {
		envConn.Close()
		return fmt.Errorf("manager: build client TLS config: %w", err)
	}
	relayConn, err := h2proxy.NewRelayTunnelConnWithMTLS(handshakeCtx, envConn, tlsCfg, true)
	if err != nil {
		envConn.Close()
		return fmt.Errorf("manager: inner mTLS handshake (client): %w", err)
	}

	m.mu.Lock()
	entry.relayConn = relayConn
	m.mu.Unlock()

	entry.peer.SetConn(relayConn)
	go m.forwardConnToTUN(entry.peer, relayConn)
	go m.sendCandidates(peerID, relayConn)
	go m.controlReadLoop(peerID, relayConn)
	slog.Info("manager: relay tunnel established (inner mTLS)", "peer_id", peerID)
	return nil
}

// directAcceptLoop accepts inbound connections on the DirectListener and
// handles both probe events (ALPN "malon-probe") and CONNECT-IP data sessions
// (ALPN "h3"). The two ALPNs share the same UDP port so that the NAT hole
// opened by the probe is reused for the subsequent CONNECT-IP connection.
func (m *Manager) probeAcceptLoop(ctx context.Context) {
	defer m.directLn.Close()
	for {
		ev, err := m.directLn.Accept(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			slog.Warn("manager: DirectListener accept error", "err", err)
			return
		}
		switch e := ev.(type) {
		case *direct.ProbeEvent:
			slog.Info("manager: inbound probe accepted", "peer_id", e.PeerID, "remote", e.RemoteAddr)
		case *direct.ConnectEvent:
			slog.Info("manager: inbound direct CONNECT-IP accepted", "peer_id", e.PeerID)
			go m.handleDirectConnect(e)
		}
	}
}

// handleDirectConnect promotes an inbound CONNECT-IP connection (from a remote
// client that dialed our DirectListener) to the active data path.
func (m *Manager) handleDirectConnect(e *direct.ConnectEvent) {
	m.mu.RLock()
	entry, ok := m.peers[e.PeerID]
	m.mu.RUnlock()
	if !ok {
		slog.Warn("manager: inbound direct CONNECT-IP from unknown peer", "peer_id", e.PeerID)
		_ = e.Conn.Close()
		return
	}

	m.mu.Lock()
	if entry.hasDirectPath {
		m.mu.Unlock()
		// Another goroutine already promoted; discard this connection.
		_ = e.Conn.Close()
		return
	}
	entry.hasDirectPath = true
	m.mu.Unlock()

	entry.peer.SetConn(e.Conn)
	go m.forwardDirectConnToTUN(e.PeerID, entry.peer, e.Conn)
	slog.Info("manager: promoted to direct path (inbound)", "peer_id", e.PeerID)
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
	handshakeCtx, cancel := context.WithTimeout(m.ctx, 10*time.Second)
	defer cancel()
	relayConn, err := h2proxy.NewRelayTunnelConnWithMTLS(handshakeCtx, envConn, tlsCfg, false)
	if err != nil {
		// This is expected when the client sends a fresh TLS ClientHello on a
		// new relay session while the proxy still has an old session open.
		// Not a fatal error — the client will immediately retry with a new session.
		slog.Warn("manager: inner mTLS handshake (server)", "peer_id", peerID, "err", err)
		envConn.Close()
		return
	}

	m.mu.Lock()
	entry.relayConn = relayConn
	m.mu.Unlock()

	entry.peer.SetConn(relayConn)
	go m.forwardConnToTUN(entry.peer, relayConn)
	go m.sendCandidates(peerID, relayConn)
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
	ctrlMsg, err := control.Decode(msg.Payload)
	if err != nil {
		slog.Debug("manager: control decode failed", "src", msg.SrcPeerID, "err", err)
		return
	}
	switch ctrlMsg.Type {
	case control.MsgTypeCandidates:
		go m.validateCandidates(msg.SrcPeerID, ctrlMsg)
	default:
		slog.Debug("manager: unknown control type", "src", msg.SrcPeerID, "type", ctrlMsg.Type)
	}
}

// sendCandidates collects candidates for this node and sends them to the
// given peer via a CONTROL capsule. Both proxy and client nodes send
// candidates: proxy sends embedded (local IPs + listen port) and STUN;
// client sends STUN only (no fixed listen port yet, but needed for future P2P
// hole punching).
func (m *Manager) sendCandidates(peerID identity.PeerID, rc *h2proxy.RelayTunnelConn) {
	if m.mion == nil {
		return
	}

	gen := m.generation

	// Collect embedded candidates using the DirectListener port.
	// The DirectListener binds its own UDP socket regardless of role, so both
	// proxy and client nodes can accept inbound probes on a known port.
	var embedded []candidate.Candidate
	if m.directLn != nil {
		port := m.directLn.LocalPort()
		var exclude []netip.Prefix
		if m.overlayPrefix.IsValid() {
			exclude = []netip.Prefix{m.overlayPrefix}
		}
		var err error
		embedded, err = candidate.CollectEmbedded(port, gen, exclude)
		if err != nil {
			slog.Warn("manager: collect embedded candidates failed", "err", err)
		}
	}

	// Collect stuned candidate via STUN (both roles).
	stunCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	srv := m.stunServer
	if srv == "" {
		srv = defaultSTUNServer
	}
	stunAddr, err := stun.Query(stunCtx, srv)
	var stunned []candidate.Candidate
	if err != nil {
		slog.Warn("manager: STUN query failed", "err", err)
	} else {
		stunned = []candidate.Candidate{{
			Kind:       candidate.KindStuned,
			Addr:       stunAddr,
			Generation: gen,
		}}
	}

	all := append(embedded, stunned...)

	if len(all) == 0 {
		return
	}

	var infos []control.CandidateInfo
	for _, c := range all {
		infos = append(infos, control.CandidateInfo{
			Kind: c.Kind.String(),
			Addr: c.Addr.String(),
		})
	}
	payload, err := control.Encode(control.Message{
		Type:       control.MsgTypeCandidates,
		Generation: gen,
		Candidates: infos,
	})
	if err != nil {
		slog.Error("manager: encode candidate message", "err", err)
		return
	}
	if err := rc.WriteControl(payload); err != nil {
		slog.Warn("manager: send candidates failed", "peer_id", peerID, "err", err)
		return
	}
	addrs := make([]string, len(all))
	for i, c := range all {
		addrs[i] = c.Kind.String() + ":" + c.Addr.String()
	}
	slog.Info("manager: sent candidates", "peer_id", peerID, "count", len(all), "addrs", addrs)
}

// validateCandidates runs DirectH3PathValidator for each candidate received
// from a peer. Successful probes are stored in m.validated for Phase 5
// path promotion.
func (m *Manager) validateCandidates(peerID identity.PeerID, msg control.Message) {
	if m.ctx == nil {
		return
	}
	recvAddrs := make([]string, len(msg.Candidates))
	for i, ci := range msg.Candidates {
		recvAddrs[i] = ci.Kind + ":" + ci.Addr
	}
	slog.Info("manager: received candidates", "peer_id", peerID, "count", len(msg.Candidates), "addrs", recvAddrs)
	for _, ci := range msg.Candidates {
		ci := ci
		addr, err := netip.ParseAddrPort(ci.Addr)
		if err != nil {
			slog.Warn("manager: invalid candidate addr", "addr", ci.Addr, "err", err)
			continue
		}
		// Skip addresses that failed recently to avoid repeated timeout spam
		// on every relay reconnect (e.g. unreachable IPv6, asymmetric NAT).
		m.probeCooldownMu.Lock()
		if until, ok := m.probeCooldown[addr]; ok && time.Now().Before(until) {
			m.probeCooldownMu.Unlock()
			slog.Debug("manager: skipping probe (cooldown)", "addr", addr, "until", until)
			continue
		}
		m.probeCooldownMu.Unlock()

		// Skip probing if a direct path is already active for this peer.
		// Once promoted, further candidate probing is unnecessary until the
		// direct path breaks and we fall back to relay.
		m.mu.RLock()
		alreadyDirect := m.peers[peerID] != nil && m.peers[peerID].hasDirectPath
		m.mu.RUnlock()
		if alreadyDirect {
			slog.Debug("manager: skipping probe (direct path active)", "addr", addr)
			continue
		}

		go func() {
			probeCtx, cancel := context.WithTimeout(m.ctx, 10*time.Second)
			defer cancel()
			result, err := m.validator.Probe(probeCtx, addr, peerID)
			if err != nil {
				// Record cooldown so the same address is not retried immediately.
				m.probeCooldownMu.Lock()
				m.probeCooldown[addr] = time.Now().Add(probeCooldownDur)
				m.probeCooldownMu.Unlock()
				slog.Warn("manager: probe failed",
					"peer_id", peerID, "addr", addr, "kind", ci.Kind, "err", err)
				return
			}
			// Clear cooldown on success so a previously-failing address can be
			// promoted again if the network topology changes.
			m.probeCooldownMu.Lock()
			delete(m.probeCooldown, addr)
			m.probeCooldownMu.Unlock()
			m.validatedMu.Lock()
			m.validated[peerID] = append(m.validated[peerID], result)
			m.validatedMu.Unlock()
			slog.Info("manager: direct path validated",
				"peer_id", peerID,
				"addr", result.RemoteAddr,
				"kind", ci.Kind,
				"rtt", result.RTT,
				"generation", msg.Generation,
			)
			// Phase 5: client role only — proxy waits for inbound connections.
			if m.mion.Role() == "client" {
				go m.tryPromotePath(peerID, result)
			}
		}()
	}
}

// tryPromotePath attempts to promote a validated direct path to the active
// data path for peerID. After a successful probe, the client dials CONNECT-IP
// to the same DirectListener address (result.RemoteAddr) that was probed.
// This reuses the NAT hole opened during probing, enabling direct connectivity
// through CGNAT without any port forwarding on the proxy side.
func (m *Manager) tryPromotePath(peerID identity.PeerID, result *h3path.ValidatedTransport) {
	m.mu.RLock()
	entry, ok := m.peers[peerID]
	alreadyDirect := entry.hasDirectPath
	m.mu.RUnlock()
	if !ok || alreadyDirect {
		return
	}

	// Dial CONNECT-IP to the same address that was probed. The probe's QUIC
	// Initial/Handshake opened a NAT mapping; this new QUIC connection reuses
	// that mapping without requiring any port forwarding on the proxy.
	conn, err := direct.Dial(m.ctx, m.selfPriv, result.RemoteAddr, peerID)
	if err != nil {
		slog.Warn("manager: direct path promotion failed",
			"peer_id", peerID, "addr", result.RemoteAddr, "err", err)
		return
	}

	// Re-check hasDirectPath under Lock after Dial (another goroutine may
	// have promoted the path while we were dialling).
	m.mu.Lock()
	e, ok2 := m.peers[peerID]
	if !ok2 || e.hasDirectPath {
		m.mu.Unlock()
		_ = conn.Close()
		return
	}
	e.hasDirectPath = true
	m.mu.Unlock()

	entry.peer.SetConn(conn)
	go m.forwardDirectConnToTUN(peerID, entry.peer, conn)
	slog.Info("manager: promoted to direct path",
		"peer_id", peerID,
		"addr", result.RemoteAddr,
		"rtt", result.RTT,
	)
}

// forwardDirectConnToTUN reads IP packets from a direct connection and writes
// them to TUN. Mirrors forwardConnToTUN but for *direct.DirectConn.
// On close, falls back to the relay path if one is available.
func (m *Manager) forwardDirectConnToTUN(peerID identity.PeerID, p *peer.Peer, dc *direct.DirectConn) {
	if m.mion == nil {
		return
	}
	tun := m.mion.TUN()
	buf := make([]byte, tun.MTU())
	for {
		n, err := dc.ReadPacket(buf)
		if err != nil {
			p.ClearConnIf(dc)
			slog.Info("manager: direct conn closed, falling back to relay",
				"peer_id", p.PeerID, "err", err)
			m.fallbackToRelay(peerID)
			return
		}
		if n == 0 {
			p.UpdateLastReceive()
			continue
		}
		pkt := buf[:n]
		p.UpdateLastReceive()
		srcIP := malonExtractSrcIP(pkt)
		if !malonAllowedIPsContains(p.AllowedIPs, srcIP) {
			slog.Warn("manager: dropping packet on direct path, src not in AllowedIPs",
				"peer_id", p.PeerID, "src", srcIP)
			continue
		}
		if _, err := tun.Write(pkt); err != nil {
			slog.Error("manager: TUN write error (direct)", "err", err)
		}
	}
}

// fallbackToRelay restores the relay conn for a peer after the direct path breaks.
// If no relay conn is stored, the peer will have no active transport until the
// relay reconnects and re-establishes the session.
func (m *Manager) fallbackToRelay(peerID identity.PeerID) {
	m.mu.Lock()
	entry, ok := m.peers[peerID]
	var oldRelayConn *h2proxy.RelayTunnelConn
	if ok {
		if !entry.hasDirectPath {
			// Another goroutine already triggered fallback; skip.
			m.mu.Unlock()
			return
		}
		entry.hasDirectPath = false
		oldRelayConn = entry.relayConn
		entry.relayConn = nil // clear so ConnectPeer will set a fresh one
	}
	m.mu.Unlock()
	if !ok {
		return
	}

	// Close the old relay conn to unblock any goroutine still reading from it.
	// The old session is stale: the remote peer may have restarted and expects a
	// fresh TLS ClientHello, not mid-session encrypted data.
	if oldRelayConn != nil {
		_ = oldRelayConn.Close()
	}

	// Only client role re-dials; proxy role waits for the client to reconnect.
	if m.mion.Role() != "client" {
		slog.Info("manager: direct path closed (proxy role), waiting for client reconnect",
			"peer_id", peerID)
		return
	}

	// Retry ConnectPeer in the background with backoff. The remote proxy may
	// not be connected to the relay yet (e.g. proxy just restarted), so a
	// single attempt is not enough.
	go m.retryConnectPeer(peerID)
}

// retryConnectPeer keeps trying to establish a relay session to peerID until
// it succeeds, the context is cancelled, or a direct path is promoted again.
func (m *Manager) retryConnectPeer(peerID identity.PeerID) {
	backoff := time.Second
	const maxBackoff = 15 * time.Second
	for {
		if m.ctx.Err() != nil {
			return
		}
		m.mu.RLock()
		e := m.peers[peerID]
		alreadyDirect := e != nil && e.hasDirectPath
		// setupRelayPeers (called by relayConnectLoop on reconnect) may have
		// already restored the relay session — if so, stop retrying.
		alreadyRelay := e != nil && e.relayConn != nil
		relayURL := ""
		if e != nil {
			relayURL = e.relayURL
		}
		m.mu.RUnlock()
		if alreadyDirect || alreadyRelay {
			return
		}

		// If the relay H2 connection itself is down, don't attempt mTLS —
		// relayConnectLoop will reconnect and call setupRelayPeers.
		// We just wait with backoff and check again.
		if relayURL != "" {
			proxy := m.getOrCreateProxy(relayURL)
			if !proxy.IsConnected() {
				slog.Debug("manager: relay not connected, waiting for relayConnectLoop",
					"peer_id", peerID, "backoff", backoff)
				select {
				case <-m.ctx.Done():
					return
				case <-time.After(backoff):
				}
				if backoff < maxBackoff {
					backoff *= 2
				}
				continue
			}
		}

		if err := m.connectPeerWithCtx(m.ctx, peerID); err == nil {
			slog.Info("manager: restored relay path after direct path failure", "peer_id", peerID)
			return
		} else {
			slog.Warn("manager: relay re-connect attempt failed, retrying",
				"peer_id", peerID, "err", err, "backoff", backoff)
		}
		select {
		case <-m.ctx.Done():
			return
		case <-time.After(backoff):
		}
		if backoff < maxBackoff {
			backoff *= 2
		}
	}
}

// forwardConnToTUN reads IP packets from a relay tunnel and writes them to
// the TUN device. This is MALON's own implementation of Conn→TUN forwarding,
// covering both client and proxy roles without relying on mion internals.
func (m *Manager) forwardConnToTUN(p *peer.Peer, rc *h2proxy.RelayTunnelConn) {
	if m.mion == nil {
		return
	}
	tun := m.mion.TUN()
	buf := make([]byte, tun.MTU())
	for {
		n, err := rc.ReadPacket(buf)
		if err != nil {
			p.ClearConnIf(rc)
			slog.Debug("manager: relay conn closed (conn→TUN)", "peer_id", p.PeerID, "err", err)
			return
		}
		// n==0 is a keepalive ping; update liveness timestamp.
		if n == 0 {
			p.UpdateLastReceive()
			continue
		}
		pkt := buf[:n]
		p.UpdateLastReceive()

		// Validate source IP against peer's AllowedIPs.
		srcIP := malonExtractSrcIP(pkt)
		if !malonAllowedIPsContains(p.AllowedIPs, srcIP) {
			slog.Warn("manager: dropping packet, src not in AllowedIPs",
				"peer_id", p.PeerID, "src", srcIP)
			continue
		}
		if _, err := tun.Write(pkt); err != nil {
			slog.Error("manager: TUN write error", "err", err)
		}
	}
}

// malonExtractSrcIP extracts the source IP address from an IPv4 or IPv6 packet.
func malonExtractSrcIP(pkt []byte) netip.Addr {
	if len(pkt) < 20 {
		return netip.Addr{}
	}
	switch pkt[0] >> 4 {
	case 4:
		return netip.AddrFrom4([4]byte(pkt[12:16]))
	case 6:
		if len(pkt) < 40 {
			return netip.Addr{}
		}
		return netip.AddrFrom16([16]byte(pkt[8:24]))
	}
	return netip.Addr{}
}

// malonAllowedIPsContains reports whether addr falls within any of the prefixes.
func malonAllowedIPsContains(prefixes []netip.Prefix, addr netip.Addr) bool {
	for _, prefix := range prefixes {
		if prefix.Contains(addr) {
			return true
		}
	}
	return false
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
