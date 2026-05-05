package direct

import (
	"context"
	"crypto/ed25519"
	"fmt"
	"net"
	"net/netip"
	"time"

	connectip "github.com/quic-go/connect-ip-go"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/yosida95/uritemplate/v3"

	"github.com/pabotesu/malon/internal/auth"
	"github.com/pabotesu/malon/internal/identity"
)

// DirectConn wraps a CONNECT-IP session established over a direct QUIC path.
// It implements the same ReadPacket/WritePacket/Close interface as relay conns.
type DirectConn struct {
	inner *connectip.Conn
}

// ReadPacket reads one IP packet from the direct path.
func (c *DirectConn) ReadPacket(buf []byte) (int, error) {
	return c.inner.ReadPacket(buf)
}

// WritePacket sends one IP packet over the direct path.
func (c *DirectConn) WritePacket(pkt []byte) error {
	_, err := c.inner.WritePacket(pkt)
	return err
}

// Close terminates the direct CONNECT-IP session.
func (c *DirectConn) Close() error {
	return c.inner.Close()
}

// Dial establishes a direct QUIC + CONNECT-IP session to the peer's
// DirectListener port (the same port that was used for the probe).
//
// Design: the probe (ALPN "malon-probe") opens a NAT mapping from the client's
// ephemeral UDP port to the peer's DirectListener port. By dialing CONNECT-IP
// (ALPN "h3") to the same addr from a new UDP socket, the QUIC Initial packet
// arrives at an already-open NAT entry on the peer side, making the connection
// work even through CGNAT without any port forwarding.
//
// addr is the validated DirectListener address returned by the probe (i.e.
// result.RemoteAddr from h3path.ValidatedTransport). It is NOT the mion h3
// proxy port (4443) — that port is inaccessible behind NAT.
func Dial(
	ctx context.Context,
	selfPriv ed25519.PrivateKey,
	addr netip.AddrPort,
	expectedPeerID identity.PeerID,
) (*DirectConn, error) {
	tlsCfg, err := auth.NewDirectClientTLSConfig(selfPriv, expectedPeerID)
	if err != nil {
		return nil, fmt.Errorf("direct: TLS config: %w", err)
	}

	udpConn, err := net.ListenUDP("udp", nil)
	if err != nil {
		return nil, fmt.Errorf("direct: listen UDP: %w", err)
	}

	tr := &quic.Transport{Conn: udpConn}
	udpAddr := net.UDPAddrFromAddrPort(addr)

	qconn, err := tr.Dial(ctx, udpAddr, tlsCfg, &quic.Config{
		EnableDatagrams: true,
		KeepAlivePeriod: 15 * time.Second,
	})
	if err != nil {
		_ = tr.Close()
		return nil, fmt.Errorf("direct: QUIC dial %s: %w", addr, err)
	}

	h3tr := &http3.Transport{EnableDatagrams: true}
	hconn := h3tr.NewClientConn(qconn)

	var authority string
	if addr.Addr().Is6() {
		authority = fmt.Sprintf("[%s]:%d", addr.Addr(), addr.Port())
	} else {
		authority = addr.String()
	}
	template := uritemplate.MustNew(fmt.Sprintf("https://%s/mion", authority))

	ipconn, _, err := connectip.Dial(ctx, hconn, template)
	if err != nil {
		_ = qconn.CloseWithError(0, "connect-ip failed")
		_ = tr.Close()
		return nil, fmt.Errorf("direct: CONNECT-IP dial %s: %w", addr, err)
	}

	return &DirectConn{inner: ipconn}, nil
}
