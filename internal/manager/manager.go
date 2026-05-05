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
	peer     *peer.Peer
	relayURL string
}

// Manager coordinates transport paths for all known peers.
// defaultSTUNServer uses the IPv4-only subdomain provided by Google to avoid
// silent failures on hosts that have IPv6 configured but no working IPv6 route.
// Port 3478 is the standard STUN port (RFC 5389) and is more likely to be
// unblocked on VPS/firewall environments than Google's alternative port 19302.
const defaultSTUNServer = "stun4.l.google.com:3478"

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

	// Phase 4+: DirectListener for accepting inbound probes.
	directLn *direct.Listener
}

// New creates a Manager.
//
//   - selfPriv: local Ed25519 private key (used to derive selfID and for inner mTLS).
//   - interfaceRelayURL: relay this node connects to regardless of peer config (proxy role).
//   - tlsInsecure: skip TLS certificate verification on the relay connection (testing only).
//   - stunServer: STUN server (host:port); empty string uses the default (stun.l.google.com:19302).
//   - m: the Mion instance; used to activate TUN forwarding after SetConn.
func New(selfPriv ed25519.PrivateKey, interfaceRelayURL string, tlsInsecure bool, stunServer string, m *mionpkg.Mion) *Manager {
	pub := selfPriv.Public().(ed25519.PublicKey)
	selfID := identity.PeerIDFromPublicKey(pub)

	controlCh := make(chan h2proxy.ControlMessage, 64)
	acceptCh := make(chan *h2proxy.EnvelopeNetConn, 16)

	mgr := &Manager{
		selfID:     selfID,
		selfPriv:   selfPriv,
		insecure:   tlsInsecure,
		stunServer: stunServer,
		peers:      make(map[identity.PeerID]*peerEntry),
		proxies:    make(map[string]*h2proxy.InternalProxy),
		controlCh:  controlCh,
		acceptCh:   acceptCh,
		mion:       m,
		validator:  h3path.New(selfPriv),
		generation: 1,
		validated:  make(map[identity.PeerID][]*h3path.ValidatedTransport),
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
		// No relay configured at all; just wait for context.
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
	go m.forwardConnToTUN(entry.peer, relayConn)
	go m.sendCandidates(peerID, relayConn)
	go m.controlReadLoop(peerID, relayConn)
	slog.Info("manager: relay tunnel established (inner mTLS)", "peer_id", peerID)
	return nil
}

// probeAcceptLoop accepts inbound "malon-probe" connections on the DirectListener
// and records them as validated paths for Phase 5 path promotion.
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
		slog.Info("manager: inbound probe accepted", "peer_id", ev.PeerID,
			"remote", ev.Conn.RemoteAddr())
		// Close the probe connection immediately — Phase 5 will reuse it for
		// path promotion once both directions succeed.
		_ = ev.Conn.CloseWithError(0, "probe ok")
	}
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
		var err error
		embedded, err = candidate.CollectEmbedded(port, gen)
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
		go func() {
			probeCtx, cancel := context.WithTimeout(m.ctx, 10*time.Second)
			defer cancel()
			result, err := m.validator.Probe(probeCtx, addr, peerID)
			if err != nil {
				slog.Warn("manager: probe failed",
					"peer_id", peerID, "addr", addr, "kind", ci.Kind, "err", err)
				return
			}
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
		}()
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
