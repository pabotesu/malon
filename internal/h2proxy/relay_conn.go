package h2proxy

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"

	"github.com/pabotesu/mion/transport"
)

// RelayTunnelConn implements transport.TunnelConn over an EnvelopeNetConn.
//
// Layer stack (with inner mTLS):
//
//	MION Core (ReadPacket / WritePacket)
//	     ↕
//	RelayTunnelConn   ← capsule framing (type=0: DATA, type=1: CONTROL)
//	     ↕
//	*tls.Conn         ← inner mTLS (ALPN="malon-relay")
//	     ↕
//	EnvelopeNetConn   ← StreamTypeData envelopes via shared HTTP/2 CONNECT
//
// Without inner mTLS (NewRelayTunnelConn), the capsule layer sits directly
// on EnvelopeNetConn and ctrlCh is nil.
type RelayTunnelConn struct {
	conn    *EnvelopeNetConn // underlying byte-stream connection
	capsule *capsuleConn     // capsule framing layer
	ctrlCh  chan []byte      // CONTROL frames; nil when no inner mTLS
}

var _ transport.TunnelConn = (*RelayTunnelConn)(nil)

// NewRelayTunnelConn creates a RelayTunnelConn wrapping envConn without inner
// mTLS. CONTROL frames are discarded (ctrlCh = nil).
func NewRelayTunnelConn(envConn *EnvelopeNetConn) *RelayTunnelConn {
	c := newCapsuleConn(envConn, envConn, envConn.Close, nil)
	return &RelayTunnelConn{
		conn:    envConn,
		capsule: c,
	}
}

// NewRelayTunnelConnWithMTLS creates a RelayTunnelConn with inner mTLS.
//   - isClient: true → tls.Client (outbound); false → tls.Server (inbound)
//   - tlsCfg: must be built by auth.NewClientTLSConfig or auth.NewServerTLSConfig
//
// The TLS handshake is performed synchronously within ctx. On success, CONTROL
// capsule frames are delivered via RelayTunnelConn.ReadControl.
func NewRelayTunnelConnWithMTLS(ctx context.Context, envConn *EnvelopeNetConn, tlsCfg *tls.Config, isClient bool) (*RelayTunnelConn, error) {
	var tlsConn *tls.Conn
	if isClient {
		tlsConn = tls.Client(envConn, tlsCfg)
	} else {
		tlsConn = tls.Server(envConn, tlsCfg)
	}
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		return nil, fmt.Errorf("h2proxy: inner mTLS handshake: %w", err)
	}
	ctrlCh := make(chan []byte, 16)
	c := newCapsuleConn(tlsConn, tlsConn, tlsConn.Close, ctrlCh)
	return &RelayTunnelConn{
		conn:    envConn,
		capsule: c,
		ctrlCh:  ctrlCh,
	}, nil
}

// ReadPacket reads one IP packet from the capsule stream.
func (r *RelayTunnelConn) ReadPacket(buf []byte) (int, error) {
	return r.capsule.ReadPacket(buf)
}

// WritePacket frames pkt as an IP_PACKET capsule and writes it.
func (r *RelayTunnelConn) WritePacket(pkt []byte) error {
	return r.capsule.WritePacket(pkt)
}

// ReadControl blocks until a CONTROL frame is received from the inner mTLS
// stream. Returns io.EOF when the connection is closed.
// Panics if called on a conn without inner mTLS (ctrlCh == nil).
func (r *RelayTunnelConn) ReadControl() ([]byte, error) {
	payload, ok := <-r.ctrlCh
	if !ok {
		return nil, io.EOF
	}
	return payload, nil
}

// WriteControl sends payload as a CONTROL capsule through the inner mTLS
// stream. Should not be called on a conn without inner mTLS.
func (r *RelayTunnelConn) WriteControl(payload []byte) error {
	return r.capsule.WriteControl(payload)
}

// Close closes the underlying EnvelopeNetConn.
func (r *RelayTunnelConn) Close() error {
	return r.capsule.Close()
}
