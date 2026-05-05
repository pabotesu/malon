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
// The underlying UDP socket (quic.Transport) is owned by the DirectListener
// and must NOT be closed here.
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
// The underlying UDP socket is owned by the DirectListener, not this conn.
func (c *DirectConn) Close() error {
	return c.inner.Close()
}

// Dial establishes a direct QUIC + CONNECT-IP session to addr using tr.
// tr MUST be the DirectListener's transport (Listener.Transport()) so that
// both the probe and the CONNECT-IP connection leave from the same UDP port.
// This ensures the QUIC Initial packet hits the NAT entry opened by the probe,
// enabling hole punching through symmetric NAT.
//
// tr is NOT owned by Dial; the DirectListener manages its lifetime.
func Dial(
	ctx context.Context,
	selfPriv ed25519.PrivateKey,
	addr netip.AddrPort,
	expectedPeerID identity.PeerID,
	tr *quic.Transport,
) (*DirectConn, error) {
	tlsCfg, err := auth.NewDirectClientTLSConfig(selfPriv, expectedPeerID)
	if err != nil {
		return nil, fmt.Errorf("direct: TLS config: %w", err)
	}

	udpAddr := net.UDPAddrFromAddrPort(addr)

	qconn, err := tr.Dial(ctx, udpAddr, tlsCfg, &quic.Config{
		EnableDatagrams: true,
		KeepAlivePeriod: 15 * time.Second,
	})
	if err != nil {
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
		return nil, fmt.Errorf("direct: CONNECT-IP dial %s: %w", addr, err)
	}

	// Advertise all IPv4 destinations so that incoming datagrams from the
	// proxy pass the destination-address check in ReadPacket on our side.
	if err := ipconn.AdvertiseRoute(ctx, []connectip.IPRoute{{
		StartIP:    netip.MustParseAddr("0.0.0.0"),
		EndIP:      netip.MustParseAddr("255.255.255.255"),
		IPProtocol: 0, // all protocols
	}}); err != nil {
		_ = qconn.CloseWithError(0, "route advertisement failed")
		return nil, fmt.Errorf("direct: CONNECT-IP route advertisement %s: %w", addr, err)
	}

	return &DirectConn{inner: ipconn}, nil
}
