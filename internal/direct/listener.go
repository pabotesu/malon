// Package direct implements the MALON DirectListener.
//
// The DirectListener binds an independent UDP socket and listens for inbound
// QUIC connections. It serves two ALPN protocols on the same port:
//
//   - "malon-probe": used by the remote peer to validate reachability (probe).
//     The QUIC Initial/Handshake packets open a NAT mapping that the next step
//     can reuse.
//
//   - "h3": used by the remote peer to establish the actual CONNECT-IP data
//     path after a successful probe. Reusing the same UDP port means the NAT
//     hole opened during probing is still valid when the client dials CONNECT-IP.
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
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"

	connectip "github.com/quic-go/connect-ip-go"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/yosida95/uritemplate/v3"

	"github.com/pabotesu/malon/internal/auth"
	"github.com/pabotesu/malon/internal/identity"
)

// ProbeEvent is produced by Listener.Accept when a peer successfully completes
// the "malon-probe" mTLS handshake with us.
type ProbeEvent struct {
	// PeerID is the verified identity of the probing peer.
	PeerID identity.PeerID
	// RemoteAddr is the observed remote address of the probe connection.
	// This is the address the client used to reach us (post-NAT).
	RemoteAddr netip.AddrPort
}

// ConnectEvent is produced by Listener.Accept when a peer establishes a
// CONNECT-IP data session ("h3" ALPN) on the same UDP port as the probe.
// The NAT hole opened during probing is reused for this connection.
type ConnectEvent struct {
	// PeerID is the verified identity of the connecting peer.
	PeerID identity.PeerID
	// Conn is the CONNECT-IP session ready to exchange IP packets.
	Conn *DirectConn
}

// Listener accepts inbound QUIC connections on its own UDP socket.
// It dispatches to ProbeEvent (ALPN "malon-probe") or ConnectEvent (ALPN "h3").
type Listener struct {
	transport *quic.Transport
	ln        *quic.Listener
	localPort uint16
	selfPriv  ed25519.PrivateKey
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
	ln, err := tr.Listen(tlsCfg, &quic.Config{EnableDatagrams: true})
	if err != nil {
		_ = tr.Close()
		return nil, fmt.Errorf("direct: listen QUIC: %w", err)
	}

	port := uint16(udpConn.LocalAddr().(*net.UDPAddr).Port)
	return &Listener{
		transport: tr,
		ln:        ln,
		localPort: port,
		selfPriv:  selfPriv,
	}, nil
}

// LocalPort returns the UDP port this listener is bound to.
// Advertise this port in embedded candidates sent to peers.
func (l *Listener) LocalPort() uint16 {
	return l.localPort
}

// Transport returns the underlying *quic.Transport (shared UDP socket).
// Callers use this to send outgoing probes and CONNECT-IP connections from
// the same port that inbound connections arrive on, which is essential for
// NAT hole punching: both sides must use the same 4-tuple that the peer is
// told about via candidates.
// The transport is owned by the Listener; do NOT call Close() on it.
func (l *Listener) Transport() *quic.Transport {
	return l.transport
}

// Accept waits for the next inbound connection and returns either a
// *ProbeEvent (ALPN "malon-probe") or *ConnectEvent (ALPN "h3").
// Invalid connections are silently rejected.
func (l *Listener) Accept(ctx context.Context) (any, error) {
	for {
		conn, err := l.ln.Accept(ctx)
		if err != nil {
			return nil, err
		}
		alpn := conn.ConnectionState().TLS.NegotiatedProtocol
		switch alpn {
		case "malon-probe":
			ev, err := l.handleProbe(conn)
			if err != nil {
				_ = conn.CloseWithError(1, "probe rejected")
				continue
			}
			return ev, nil
		case "h3":
			ev, err := l.handleConnect(conn)
			if err != nil {
				_ = conn.CloseWithError(1, "connect rejected")
				continue
			}
			return ev, nil
		default:
			_ = conn.CloseWithError(1, "unknown alpn")
		}
	}
}

// handleProbe handles an inbound "malon-probe" connection.
func (l *Listener) handleProbe(conn *quic.Conn) (*ProbeEvent, error) {
	peerID, err := peerIDFromConn(conn)
	if err != nil {
		return nil, err
	}
	ra := conn.RemoteAddr().(*net.UDPAddr)
	remoteAddr := netip.AddrPortFrom(ra.AddrPort().Addr().Unmap(), uint16(ra.Port))
	// Close the probe QUIC connection — its purpose was only to open the NAT
	// mapping. The client will immediately re-dial with ALPN "h3".
	_ = conn.CloseWithError(0, "probe ok")
	return &ProbeEvent{PeerID: peerID, RemoteAddr: remoteAddr}, nil
}

// handleConnect handles an inbound "h3" CONNECT-IP connection.
// It runs an HTTP/3 server on the accepted QUIC connection, waits for the
// client's CONNECT-IP request at /mion, and returns the resulting session.
func (l *Listener) handleConnect(conn *quic.Conn) (*ConnectEvent, error) {
	peerID, err := peerIDFromConn(conn)
	if err != nil {
		return nil, err
	}

	type result struct {
		ipconn *connectip.Conn
		err    error
	}
	ch := make(chan result, 1)
	prxy := &connectip.Proxy{}

	h3srv := &http3.Server{
		EnableDatagrams: true,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Build the template from the incoming :authority header so that
			// ParseRequest's host-equality check always passes. The client sends
			// its view of our address (e.g. the NAT-mapped external IP:port), which
			// differs from our locally bound address and cannot be known in advance.
			tmpl := uritemplate.MustNew("https://" + r.Host + "/mion")
			req, parseErr := connectip.ParseRequest(r, tmpl)
			if parseErr != nil {
				var rpe *connectip.RequestParseError
				status := http.StatusBadRequest
				if errors.As(parseErr, &rpe) {
					status = rpe.HTTPStatus
				}
				http.Error(w, parseErr.Error(), status)
				ch <- result{err: parseErr}
				return
			}
			ipconn, proxyErr := prxy.Proxy(w, req)
			if proxyErr != nil {
				ch <- result{err: proxyErr}
				return
			}
			// Advertise all IPv4 destinations so that incoming datagrams from
			// the peer pass the destination-address check in ReadPacket.
			// Without this, connect-ip-go drops every packet because no
			// routes have been declared as acceptable.
			advErr := ipconn.AdvertiseRoute(r.Context(), []connectip.IPRoute{{
				StartIP:    netip.MustParseAddr("0.0.0.0"),
				EndIP:      netip.MustParseAddr("255.255.255.255"),
				IPProtocol: 0, // all protocols
			}})
			if advErr != nil {
				ch <- result{err: advErr}
				return
			}
			ch <- result{ipconn: ipconn}
		}),
	}
	go func() { _ = h3srv.ServeQUICConn(conn) }()

	res := <-ch
	if res.err != nil {
		return nil, fmt.Errorf("direct: CONNECT-IP server: %w", res.err)
	}
	return &ConnectEvent{PeerID: peerID, Conn: &DirectConn{inner: res.ipconn}}, nil
}

// peerIDFromConn extracts and validates the peer identity from the TLS state.
func peerIDFromConn(conn *quic.Conn) (identity.PeerID, error) {
	tlsState := conn.ConnectionState().TLS
	if len(tlsState.PeerCertificates) == 0 {
		return identity.PeerID{}, fmt.Errorf("direct: no peer certificate")
	}
	pub, ok := tlsState.PeerCertificates[0].PublicKey.(ed25519.PublicKey)
	if !ok {
		return identity.PeerID{}, fmt.Errorf("direct: peer certificate is not Ed25519")
	}
	return identity.PeerIDFromPublicKey(pub), nil
}

// Close shuts down the listener and releases the UDP socket.
func (l *Listener) Close() error {
	_ = l.ln.Close()
	return l.transport.Close()
}
