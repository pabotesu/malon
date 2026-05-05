package h2proxy

import (
	"github.com/pabotesu/mion/transport"
)

// RelayTunnelConn implements transport.TunnelConn over an EnvelopeNetConn.
//
// Layer stack:
//
//	MION Core (ReadPacket / WritePacket)
//	     ↕
//	RelayTunnelConn   ← capsule framing (RFC 9297)
//	     ↕
//	*tls.Conn         ← inner mTLS (ALPN="malon-relay") [added in M3 step 2]
//	     ↕
//	EnvelopeNetConn   ← DATA envelopes via shared HTTP/2 CONNECT stream
//
// In M3 step 1 (no inner mTLS), the capsuleConn reads/writes directly from
// the EnvelopeNetConn without a TLS layer.
type RelayTunnelConn struct {
	conn    *EnvelopeNetConn // underlying byte-stream connection
	capsule *capsuleConn     // capsule framing layer
}

var _ transport.TunnelConn = (*RelayTunnelConn)(nil)

// NewRelayTunnelConn creates a RelayTunnelConn wrapping envConn.
// This is the M3 step-1 variant (no inner mTLS).
func NewRelayTunnelConn(envConn *EnvelopeNetConn) *RelayTunnelConn {
	c := newCapsuleConn(envConn, envConn, envConn.Close)
	return &RelayTunnelConn{
		conn:    envConn,
		capsule: c,
	}
}

// ReadPacket reads one IP packet from the capsule stream.
func (r *RelayTunnelConn) ReadPacket(buf []byte) (int, error) {
	return r.capsule.ReadPacket(buf)
}

// WritePacket frames pkt as an IP_PACKET capsule and writes it.
func (r *RelayTunnelConn) WritePacket(pkt []byte) error {
	return r.capsule.WritePacket(pkt)
}

// Close closes the underlying EnvelopeNetConn.
func (r *RelayTunnelConn) Close() error {
	return r.capsule.Close()
}
