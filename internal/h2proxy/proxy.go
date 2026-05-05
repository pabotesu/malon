package h2proxy

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"sync"
	"sync/atomic"

	"github.com/pabotesu/malon/internal/envelope"
	"github.com/pabotesu/malon/internal/identity"
	"golang.org/x/net/http2"
)

// ControlMessage is a CONTROL-type envelope delivered to the Transport Manager.
type ControlMessage struct {
	SrcPeerID identity.PeerID
	Payload   []byte
}

// sessionEntry holds the per-session receive channel and its close-once guard.
type sessionEntry struct {
	ch     chan []byte
	peerID identity.PeerID
	once   sync.Once
}

// closeOnce closes ch exactly once, making pending/future Read calls return io.EOF.
func (s *sessionEntry) closeOnce() {
	s.once.Do(func() { close(s.ch) })
}

// InternalProxy maintains one HTTP/2 CONNECT stream to the MALON Relay and
// multiplexes per-peer DATA sessions and CONTROL messages over it.
//
// Locking discipline:
//   - wrMu  protects writer (the shared CONNECT stream write end).
//   - sessMu protects sessions map. Channel sends are done outside sessMu.
type InternalProxy struct {
	selfID      identity.PeerID
	relayURL    string // e.g. "https://relay.example.com:443"
	tlsInsecure bool   // skip TLS certificate verification (testing only)

	controlCh chan<- ControlMessage // CONTROL envelopes → Transport Manager
	acceptCh  chan *EnvelopeNetConn // incoming sessions from remote peers

	wrMu   sync.Mutex
	writer io.Writer // nil until Connect succeeds

	sessMu   sync.Mutex
	sessions map[envelope.SessionID]*sessionEntry
	nextSID  atomic.Uint32

	connMu      sync.Mutex
	connectedCh chan struct{} // closed when the CONNECT stream is established; Reset() for each reconnect
}

// NewProxy creates an InternalProxy.
//
//   - controlCh receives CONTROL envelopes; must be read by Transport Manager.
//   - acceptCh  receives incoming EnvelopeNetConns initiated by remote peers.
func NewProxy(
	selfID identity.PeerID,
	relayURL string,
	controlCh chan<- ControlMessage,
	acceptCh chan *EnvelopeNetConn,
	tlsInsecure bool,
) *InternalProxy {
	return &InternalProxy{
		selfID:      selfID,
		relayURL:    relayURL,
		tlsInsecure: tlsInsecure,
		controlCh:   controlCh,
		acceptCh:    acceptCh,
		sessions:    make(map[envelope.SessionID]*sessionEntry),
		connectedCh: make(chan struct{}),
	}
}

// Reset prepares the InternalProxy for a new Connect attempt by creating a
// fresh connectedCh. Must be called before each Connect call (except the first).
func (p *InternalProxy) Reset() {
	p.connMu.Lock()
	p.connectedCh = make(chan struct{})
	p.connMu.Unlock()
}

// Connected returns a channel that is closed when the current relay CONNECT
// stream is established. A new channel is issued after each Reset+Connect cycle.
func (p *InternalProxy) Connected() <-chan struct{} {
	p.connMu.Lock()
	ch := p.connectedCh
	p.connMu.Unlock()
	return ch
}

// Connect dials the Relay via HTTP/2 CONNECT and starts the readLoop.
// It blocks until the connection is closed or ctx is cancelled.
// The caller should retry with back-off on error.
func (p *InternalProxy) Connect(ctx context.Context) error {
	u, err := url.Parse(p.relayURL)
	if err != nil {
		return fmt.Errorf("h2proxy: parse relay URL: %w", err)
	}

	var transport *http2.Transport
	if u.Scheme == "https" {
		transport = &http2.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: p.tlsInsecure, //nolint:gosec // intentional for testing
				MinVersion:         tls.VersionTLS13,
			},
		}
	} else {
		transport = &http2.Transport{
			AllowHTTP: true,
		}
	}

	pr, pw := io.Pipe()
	req, err := http.NewRequestWithContext(ctx, http.MethodConnect, p.relayURL, pr)
	if err != nil {
		return fmt.Errorf("h2proxy: build request: %w", err)
	}
	req.Header.Set("X-Peer-Id", p.selfID.String())

	resp, err := transport.RoundTrip(req)
	if err != nil {
		return fmt.Errorf("h2proxy: CONNECT to relay: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("h2proxy: relay returned status %d", resp.StatusCode)
	}

	p.wrMu.Lock()
	p.writer = pw
	p.wrMu.Unlock()

	// Signal waiters that the relay is ready for this connect attempt.
	p.connMu.Lock()
	ch := p.connectedCh
	p.connMu.Unlock()
	close(ch)

	slog.Info("h2proxy: connected to relay", "relay", p.relayURL)
	defer func() {
		slog.Info("h2proxy: relay connection closed, cleaning up sessions")
		p.wrMu.Lock()
		p.writer = nil
		p.wrMu.Unlock()
		p.closeAllSessions()
		pw.Close()
	}()

	return p.readLoop(resp.Body)
}

// readLoop reads Envelopes from the CONNECT stream body and dispatches them.
func (p *InternalProxy) readLoop(r io.Reader) error {
	for {
		env, err := envelope.Decode(r)
		if err != nil {
			return err
		}
		switch env.StreamType {
		case envelope.StreamTypeData:
			p.dispatchData(env)
		case envelope.StreamTypeControl:
			p.dispatchControl(env)
		default:
			slog.Warn("h2proxy: unknown stream_type", "type", env.StreamType)
		}
	}
}

// dispatchData routes a DATA envelope to the correct session channel.
// If the session_id is new, a fresh EnvelopeNetConn is offered to acceptCh.
func (p *InternalProxy) dispatchData(env envelope.Envelope) {
	p.sessMu.Lock()
	s, ok := p.sessions[env.SessionID]
	if !ok {
		// New incoming session from a remote peer.
		s = &sessionEntry{
			ch:     make(chan []byte, 64),
			peerID: env.SrcPeerID,
		}
		p.sessions[env.SessionID] = s
		// Buffer the first packet before exposing the conn to acceptCh.
		safeSend(s.ch, env.Payload)
		conn := &EnvelopeNetConn{
			proxy:     p,
			sessionID: env.SessionID,
			peerID:    env.SrcPeerID,
			recvCh:    s.ch,
		}
		p.sessMu.Unlock()

		select {
		case p.acceptCh <- conn:
		default:
			slog.Warn("h2proxy: acceptCh full, dropping incoming session",
				"session_id", env.SessionID, "src", env.SrcPeerID)
			p.removeSession(env.SessionID)
		}
		return
	}
	ch := s.ch
	p.sessMu.Unlock()

	safeSend(ch, env.Payload)
}

// dispatchControl forwards a CONTROL envelope to the Transport Manager.
func (p *InternalProxy) dispatchControl(env envelope.Envelope) {
	msg := ControlMessage{SrcPeerID: env.SrcPeerID, Payload: env.Payload}
	select {
	case p.controlCh <- msg:
	default:
		slog.Warn("h2proxy: controlCh full, dropping control message", "src", env.SrcPeerID)
	}
}

// NewSession creates an outgoing EnvelopeNetConn to peerID.
// The session is registered immediately; data can be written before the
// remote side acks (the relay forwards everything).
func (p *InternalProxy) NewSession(peerID identity.PeerID) *EnvelopeNetConn {
	sid := envelope.SessionID(p.nextSID.Add(1))
	s := &sessionEntry{
		ch:     make(chan []byte, 64),
		peerID: peerID,
	}
	p.sessMu.Lock()
	p.sessions[sid] = s
	p.sessMu.Unlock()

	return &EnvelopeNetConn{
		proxy:     p,
		sessionID: sid,
		peerID:    peerID,
		recvCh:    s.ch,
	}
}

// SendControl sends a CONTROL envelope to peerID via the shared stream.
func (p *InternalProxy) SendControl(peerID identity.PeerID, payload []byte) error {
	return p.writeEnvelope(envelope.Envelope{
		Version:    envelope.Version1,
		StreamType: envelope.StreamTypeControl,
		SrcPeerID:  p.selfID,
		DstPeerID:  peerID,
		Payload:    payload,
	})
}

// writeEnvelope serialises env and writes it to the shared CONNECT stream.
// Concurrent callers are serialised by wrMu.
func (p *InternalProxy) writeEnvelope(env envelope.Envelope) error {
	p.wrMu.Lock()
	defer p.wrMu.Unlock()
	if p.writer == nil {
		return fmt.Errorf("h2proxy: not connected to relay")
	}
	return envelope.Encode(p.writer, env)
}

// removeSession closes the session's channel and removes it from the map.
// Safe to call from EnvelopeNetConn.Close and from readLoop cleanup.
func (p *InternalProxy) removeSession(sid envelope.SessionID) {
	p.sessMu.Lock()
	defer p.sessMu.Unlock()
	if s, ok := p.sessions[sid]; ok {
		s.closeOnce()
		delete(p.sessions, sid)
	}
}

// closeAllSessions closes every session channel, causing all pending
// EnvelopeNetConn.Read calls to return io.EOF.
func (p *InternalProxy) closeAllSessions() {
	p.sessMu.Lock()
	defer p.sessMu.Unlock()
	for sid, s := range p.sessions {
		s.closeOnce()
		delete(p.sessions, sid)
	}
}

// safeSend sends data to ch without blocking. Panics from closed channels
// are recovered silently.
func safeSend(ch chan []byte, data []byte) {
	defer func() { recover() }() //nolint:errcheck
	select {
	case ch <- data:
	default:
		// Drop packet if channel buffer is full.
	}
}
