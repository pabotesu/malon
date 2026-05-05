// Package auth implements Ed25519-based inner mTLS for MALON Relay connections.
//
// TLS certificates use the node's own Ed25519 key pair.
// Peer authentication is performed by deriving a PeerID from the peer's
// certificate public key and checking it against the set of known peers.
// No CA chain is used; InsecureSkipVerify is combined with VerifyPeerCertificate.
package auth

import (
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"fmt"

	"github.com/pabotesu/malon/internal/identity"
)

const (
	alpnMalonRelay = "malon-relay"
	alpnMalonProbe = "malon-probe"
)

// NewClientTLSConfig returns a *tls.Config for the initiating side of the
// inner mTLS handshake (relay client / outbound connection).
func NewClientTLSConfig(
	selfPriv ed25519.PrivateKey,
	knownPeers map[identity.PeerID]struct{},
) (*tls.Config, error) {
	cert, err := selfCert(selfPriv)
	if err != nil {
		return nil, err
	}
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		// InsecureSkipVerify is intentional: CA chain is not used.
		// Peer identity is verified by VerifyPeerCertificate below.
		InsecureSkipVerify:    true, //nolint:gosec
		MinVersion:            tls.VersionTLS13,
		NextProtos:            []string{alpnMalonRelay},
		VerifyPeerCertificate: makePeerVerifier(knownPeers),
	}, nil
}

// NewServerTLSConfig returns a *tls.Config for the accepting side of the
// inner mTLS handshake (relay proxy / inbound connection).
func NewServerTLSConfig(
	selfPriv ed25519.PrivateKey,
	knownPeers map[identity.PeerID]struct{},
) (*tls.Config, error) {
	cert, err := selfCert(selfPriv)
	if err != nil {
		return nil, err
	}
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		// Require client certificate for mutual auth; verified below.
		ClientAuth:            tls.RequireAnyClientCert,
		InsecureSkipVerify:    true, //nolint:gosec
		MinVersion:            tls.VersionTLS13,
		NextProtos:            []string{alpnMalonRelay},
		VerifyPeerCertificate: makePeerVerifier(knownPeers),
	}, nil
}

// NewProbeClientTLSConfig returns a TLS config for DirectH3 path probe
// connections to a peer's DirectListener (ALPN "malon-probe").
// The probe verifies that the remote cert belongs to expectedPeerID.
func NewProbeClientTLSConfig(
	selfPriv ed25519.PrivateKey,
	expectedPeerID identity.PeerID,
) (*tls.Config, error) {
	cert, err := selfCert(selfPriv)
	if err != nil {
		return nil, err
	}
	knownPeers := map[identity.PeerID]struct{}{expectedPeerID: {}}
	return &tls.Config{
		Certificates:          []tls.Certificate{cert},
		InsecureSkipVerify:    true, //nolint:gosec
		MinVersion:            tls.VersionTLS13,
		NextProtos:            []string{alpnMalonProbe},
		VerifyPeerCertificate: makePeerVerifier(knownPeers),
	}, nil
}

// NewDirectClientTLSConfig returns a TLS config for establishing a direct
// CONNECT-IP session to a peer's mion proxy h3 endpoint (ALPN "h3").
// Used by Phase 5 path promotion after a probe has succeeded.
func NewDirectClientTLSConfig(
	selfPriv ed25519.PrivateKey,
	expectedPeerID identity.PeerID,
) (*tls.Config, error) {
	cert, err := selfCert(selfPriv)
	if err != nil {
		return nil, err
	}
	knownPeers := map[identity.PeerID]struct{}{expectedPeerID: {}}
	return &tls.Config{
		Certificates:          []tls.Certificate{cert},
		InsecureSkipVerify:    true, //nolint:gosec
		MinVersion:            tls.VersionTLS13,
		NextProtos:            []string{"h3"},
		VerifyPeerCertificate: makePeerVerifier(knownPeers),
	}, nil
}

// NewProbeServerTLSConfig returns a TLS config for the DirectListener server
// side (ALPN "malon-probe"). Inbound probe connections must present a
// certificate from a known peer.
func NewProbeServerTLSConfig(
	selfPriv ed25519.PrivateKey,
	knownPeers map[identity.PeerID]struct{},
) (*tls.Config, error) {
	cert, err := selfCert(selfPriv)
	if err != nil {
		return nil, err
	}
	return &tls.Config{
		Certificates:          []tls.Certificate{cert},
		ClientAuth:            tls.RequireAnyClientCert,
		InsecureSkipVerify:    true, //nolint:gosec
		MinVersion:            tls.VersionTLS13,
		NextProtos:            []string{alpnMalonProbe},
		VerifyPeerCertificate: makePeerVerifier(knownPeers),
	}, nil
}

// selfCert builds a tls.Certificate from the node's Ed25519 private key.
func selfCert(priv ed25519.PrivateKey) (tls.Certificate, error) {
	_, certDER, err := identity.SelfSignedCert(priv)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("auth: generate self-signed cert: %w", err)
	}
	return tls.Certificate{
		Certificate: [][]byte{certDER},
		PrivateKey:  priv,
	}, nil
}

// makePeerVerifier returns a VerifyPeerCertificate function that checks
// whether the peer's Ed25519 public key maps to a known PeerID.
func makePeerVerifier(knownPeers map[identity.PeerID]struct{}) func([][]byte, [][]*x509.Certificate) error {
	return func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
		if len(rawCerts) == 0 {
			return fmt.Errorf("auth: no peer certificate presented")
		}
		cert, err := x509.ParseCertificate(rawCerts[0])
		if err != nil {
			return fmt.Errorf("auth: parse peer certificate: %w", err)
		}
		pub, ok := cert.PublicKey.(ed25519.PublicKey)
		if !ok {
			return fmt.Errorf("auth: peer certificate has non-Ed25519 public key")
		}
		peerID := identity.PeerIDFromPublicKey(pub)
		if _, known := knownPeers[peerID]; !known {
			return fmt.Errorf("auth: peer %s is not a known peer", peerID)
		}
		return nil
	}
}
