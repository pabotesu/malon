// Package direct implements the MALON DirectListener.
//
// The DirectListener binds an independent UDP socket and listens for inbound
// QUIC connections with ALPN "malon-probe". Both the client and proxy roles
// use this package to accept direct-path probes from remote peers.
//
// Design rationale: quic-go's quic.Transport supports only one concurrent
// listener, so DirectListener always uses its own UDP socket rather than
// sharing mion's transport. This keeps the implementation uniform across roles
// and avoids any coupling to mion internals.
//
// Usage:
//
//	ln, err := direct.New(selfPriv, knownPeers)
//	// advertise ln.LocalPort() as an embedded candidate
//	ev, err := ln.Accept(ctx) // blocks until a peer probes us
package direct

import (
	"context"
	"crypto/ed25519"
	"fmt"
	"net"

	"github.com/quic-go/quic-go"

	"github.com/pabotesu/malon/internal/auth"
	"github.com/pabotesu/malon/internal/identity"
)

// ProbeEvent is produced by Listener.Accept when a peer successfully completes
// the "malon-probe" mTLS handshake with us.
type ProbeEvent struct {
	// PeerID is the verified identity of the probing peer.
	PeerID identity.PeerID
	// Conn is the accepted QUIC connection. Phase 5 can promote this to an
	// active path by wrapping it in a stream and calling peer.Peer.SetConn.
	Conn *quic.Conn
}

// Listener accepts inbound "malon-probe" QUIC connections on its own UDP socket.
type Listener struct {
	transport *quic.Transport
	ln        *quic.Listener
	localPort uint16
}

// New creates a DirectListener bound to an OS-assigned UDP port.
// knownPeers is the current set of authorized peer IDs; inbound connections
// from unknown peers are rejected at the TLS layer.
func New(selfPriv ed25519.PrivateKey, knownPeers map[identity.PeerID]struct{}) (*Listener, error) {
	tlsCfg, err := auth.NewProbeServerTLSConfig(selfPriv, knownPeers)
	if err != nil {
		return nil, fmt.Errorf("direct: build TLS config: %w", err)
	}

	udpConn, err := net.ListenUDP("udp4", &net.UDPAddr{})
	if err != nil {
		return nil, fmt.Errorf("direct: listen UDP: %w", err)
	}

	tr := &quic.Transport{Conn: udpConn}
	ln, err := tr.Listen(tlsCfg, &quic.Config{})
	if err != nil {
		_ = tr.Close()
		return nil, fmt.Errorf("direct: listen QUIC: %w", err)
	}

	port := uint16(udpConn.LocalAddr().(*net.UDPAddr).Port)
	return &Listener{
		transport: tr,
		ln:        ln,
		localPort: port,
	}, nil
}

// LocalPort returns the UDP port this listener is bound to.
// Advertise this port in embedded candidates sent to peers.
func (l *Listener) LocalPort() uint16 {
	return l.localPort
}

// Accept waits for the next inbound probe and returns it after verifying the
// peer identity from the mTLS certificate. Invalid connections are silently
// rejected and the method loops to wait for the next one.
func (l *Listener) Accept(ctx context.Context) (*ProbeEvent, error) {
	for {
		conn, err := l.ln.Accept(ctx)
		if err != nil {
			return nil, err
		}
		ev, err := l.verifyConn(conn)
		if err != nil {
			_ = conn.CloseWithError(1, "probe rejected")
			continue
		}
		return ev, nil
	}
}

// verifyConn extracts and validates the peer identity from the TLS state of
// an accepted QUIC connection.
func (l *Listener) verifyConn(conn *quic.Conn) (*ProbeEvent, error) {
	tlsState := conn.ConnectionState().TLS
	if len(tlsState.PeerCertificates) == 0 {
		return nil, fmt.Errorf("direct: no peer certificate")
	}
	pub, ok := tlsState.PeerCertificates[0].PublicKey.(ed25519.PublicKey)
	if !ok {
		return nil, fmt.Errorf("direct: peer certificate is not Ed25519")
	}
	peerID := identity.PeerIDFromPublicKey(pub)
	return &ProbeEvent{PeerID: peerID, Conn: conn}, nil
}

// Close shuts down the listener and releases the UDP socket.
func (l *Listener) Close() error {
	_ = l.ln.Close()
	return l.transport.Close()
}
