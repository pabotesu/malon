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
	inner     *connectip.Conn
	transport *quic.Transport // underlying UDP socket; closed when DirectConn closes
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

// Close terminates the direct CONNECT-IP session and releases the UDP socket.
func (c *DirectConn) Close() error {
	err := c.inner.Close()
	_ = c.transport.Close()
	return err
}

// Dial establishes a direct QUIC + CONNECT-IP session to addr using tr, which
// is the *quic.Transport returned by h3path.Validator.Probe(). Reusing the
// same transport (UDP socket / local port) means the CONNECT-IP Initial packet
// is sent from the exact same (src-IP, src-port) that the probe used, so it
// hits the NAT entry the probe already opened — enabling hole punching through
// symmetric NAT, not just cone NAT.
//
// Ownership of tr transfers to the returned DirectConn; Close() will release it.
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

	return &DirectConn{inner: ipconn, transport: tr}, nil
}
