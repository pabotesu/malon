// Package relay implements the MALON Relay server.
//
// The Relay accepts HTTP/2 CONNECT streams from peers and forwards
// MALON Envelopes based solely on dst_peer_id. It does not inspect
// or decrypt payloads.
package relay

import (
	"crypto/tls"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"sync"

	"github.com/pabotesu/malon/internal/envelope"
	"github.com/pabotesu/malon/internal/identity"
	"golang.org/x/net/http2"
)

// Relay is the MALON Relay server. It maintains one HTTP/2 CONNECT
// stream per peer and forwards Envelopes by dst_peer_id.
type Relay struct {
	mu      sync.RWMutex
	streams map[identity.PeerID]io.Writer
}

// New creates a new Relay.
func New() *Relay {
	return &Relay{
		streams: make(map[identity.PeerID]io.Writer),
	}
}

// ListenAndServe starts the Relay on the given address with TLS.
func (r *Relay) ListenAndServe(addr, certFile, keyFile string) error {
	srv := &http.Server{
		Addr:    addr,
		Handler: http.HandlerFunc(r.handleHTTP),
		TLSConfig: &tls.Config{
			MinVersion: tls.VersionTLS13,
			// Disable post-quantum KEX (X25519MLKEM768, default in Go 1.24+).
			// Some middleboxes/ISPs drop the oversized TLS ClientHello it produces.
			CurvePreferences: []tls.CurveID{tls.X25519, tls.CurveP256, tls.CurveP384},
		},
	}
	if err := http2.ConfigureServer(srv, &http2.Server{}); err != nil {
		return fmt.Errorf("relay: configure http2: %w", err)
	}
	slog.Info("relay: listening", "addr", addr)
	return srv.ListenAndServeTLS(certFile, keyFile)
}

// handleHTTP routes CONNECT requests to handleConnect and rejects others.
func (r *Relay) handleHTTP(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodConnect {
		http.Error(w, "only CONNECT is supported", http.StatusMethodNotAllowed)
		return
	}
	r.handleConnect(w, req)
}

// handleConnect registers the peer's CONNECT stream and forwards inbound
// Envelopes to the appropriate destination stream.
func (r *Relay) handleConnect(w http.ResponseWriter, req *http.Request) {
	peerIDStr := req.Header.Get("X-Peer-Id")
	if peerIDStr == "" {
		http.Error(w, "missing X-Peer-Id", http.StatusBadRequest)
		return
	}
	peerID, err := identity.PeerIDFromBase64(peerIDStr)
	if err != nil {
		http.Error(w, "invalid X-Peer-Id", http.StatusBadRequest)
		return
	}

	// Signal that the CONNECT tunnel is established.
	w.WriteHeader(http.StatusOK)
	flusher, ok := w.(http.Flusher)
	if !ok {
		slog.Error("relay: ResponseWriter does not implement http.Flusher")
		return
	}
	flusher.Flush()

	r.register(peerID, w)
	slog.Info("relay: peer connected", "peer_id", peerID)
	defer func() {
		r.unregister(peerID)
		slog.Info("relay: peer disconnected", "peer_id", peerID)
	}()

	// Read Envelopes from this peer and forward them.
	body := req.Body
	for {
		env, err := envelope.Decode(body)
		if err != nil {
			if err != io.EOF {
				slog.Warn("relay: decode envelope", "peer_id", peerID, "err", err)
			}
			return
		}
		if err := r.forward(env); err != nil {
			slog.Warn("relay: forward", "dst", env.DstPeerID, "err", err)
		}
	}
}

func (r *Relay) register(id identity.PeerID, w io.Writer) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.streams[id] = w
}

func (r *Relay) unregister(id identity.PeerID) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.streams, id)
}

func (r *Relay) forward(env envelope.Envelope) error {
	r.mu.RLock()
	dst, ok := r.streams[env.DstPeerID]
	r.mu.RUnlock()
	if !ok {
		return fmt.Errorf("peer not connected: %s", env.DstPeerID)
	}
	if err := envelope.Encode(dst, env); err != nil {
		return fmt.Errorf("encode to dst: %w", err)
	}
	// Flush if the destination supports it.
	if f, ok := dst.(http.Flusher); ok {
		f.Flush()
	}
	return nil
}

// Serve は net.Listener を受け取って TLS なしで動かす（テスト用）。
func (r *Relay) Serve(ln net.Listener) error {
	srv := &http.Server{
		Handler: http.HandlerFunc(r.handleHTTP),
	}
	if err := http2.ConfigureServer(srv, &http2.Server{}); err != nil {
		return fmt.Errorf("relay: configure http2: %w", err)
	}
	return srv.Serve(ln)
}
