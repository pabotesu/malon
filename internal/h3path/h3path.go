// Package h3path implements the DirectH3PathValidator (Phase 4).
//
// The validator probes candidate direct addresses by establishing a QUIC
// connection to the peer's mion proxy listener and completing the mTLS
// handshake. No application-layer data is exchanged — the probe verifies
// only that:
//  1. A QUIC connection can be established to the candidate addr.
//  2. The TLS handshake succeeds with ALPN "h3".
//  3. The remote certificate maps to the expected PeerID via Ed25519.
//
// Successful probes produce a ValidatedTransport that the Transport Manager
// can promote to an active direct path (Phase 5).
package h3path

import (
	"context"
	"crypto/ed25519"
	"fmt"
	"net"
	"net/netip"
	"time"

	"github.com/quic-go/quic-go"

	"github.com/pabotesu/malon/internal/auth"
	"github.com/pabotesu/malon/internal/identity"
)

// ValidatedTransport is the result of a successful DirectH3 probe.
type ValidatedTransport struct {
	// RemoteAddr is the direct address of the remote peer that was probed.
	RemoteAddr netip.AddrPort
	// PeerID is the verified remote peer identity (from mTLS cert).
	PeerID identity.PeerID
	// RTT is the QUIC handshake latency (proxy for path RTT).
	RTT time.Duration
}

// Validator probes candidate addresses via QUIC + mTLS.
type Validator struct {
	selfPriv ed25519.PrivateKey
}

// New creates a Validator using the node's Ed25519 private key.
func New(selfPriv ed25519.PrivateKey) *Validator {
	return &Validator{selfPriv: selfPriv}
}

// Probe dials addr via QUIC, completes the mTLS handshake, verifies that the
// remote peer certificate matches expectedPeerID, and returns a
// ValidatedTransport. The QUIC connection is closed immediately after
// verification — no HTTP/3 or CONNECT-IP data is sent.
func (v *Validator) Probe(ctx context.Context, addr netip.AddrPort, expectedPeerID identity.PeerID) (*ValidatedTransport, error) {
	tlsCfg, err := auth.NewProbeClientTLSConfig(v.selfPriv, expectedPeerID)
	if err != nil {
		return nil, fmt.Errorf("h3path: TLS config: %w", err)
	}

	udpConn, err := net.ListenUDP("udp", nil)
	if err != nil {
		return nil, fmt.Errorf("h3path: listen UDP: %w", err)
	}
	defer udpConn.Close()

	transport := &quic.Transport{Conn: udpConn}
	defer transport.Close()

	udpAddr := net.UDPAddrFromAddrPort(addr)

	start := time.Now()
	qconn, err := transport.Dial(ctx, udpAddr, tlsCfg, &quic.Config{
		HandshakeIdleTimeout: 5 * time.Second,
	})
	if err != nil {
		return nil, fmt.Errorf("h3path: QUIC dial %s: %w", addr, err)
	}
	defer qconn.CloseWithError(0, "probe done")

	rtt := time.Since(start)

	// Verify that the remote certificate belongs to expectedPeerID.
	tlsState := qconn.ConnectionState().TLS
	if len(tlsState.PeerCertificates) == 0 {
		return nil, fmt.Errorf("h3path: no peer certificate from %s", addr)
	}
	pub, ok := tlsState.PeerCertificates[0].PublicKey.(ed25519.PublicKey)
	if !ok {
		return nil, fmt.Errorf("h3path: peer certificate is not Ed25519 at %s", addr)
	}
	gotPeerID := identity.PeerIDFromPublicKey(pub)
	if gotPeerID != expectedPeerID {
		return nil, fmt.Errorf("h3path: peer_id mismatch at %s: got %s, want %s",
			addr, gotPeerID, expectedPeerID)
	}

	return &ValidatedTransport{
		RemoteAddr: addr,
		PeerID:     expectedPeerID,
		RTT:        rtt,
	}, nil
}
