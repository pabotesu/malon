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

// Dial establishes a direct QUIC + CONNECT-IP session to addr, verifying that
// the remote node's mTLS certificate belongs to expectedPeerID.
// addr is the DirectListener port on the remote peer (ALPN "malon-probe" for
// the handshake, then upgrading to CONNECT-IP on the proxy's h3 endpoint).
//
// Design note: the DirectListener (ALPN "malon-probe") is used only for
// reachability probing. The actual data path is established by dialing the
// remote peer's mion proxy h3 endpoint (ALPN "h3") directly. proxyAddr is
// the mion proxy h3 address (host:port from the peer config).
func Dial(
	ctx context.Context,
	selfPriv ed25519.PrivateKey,
	proxyAddr netip.AddrPort,
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
	udpAddr := net.UDPAddrFromAddrPort(proxyAddr)

	qconn, err := tr.Dial(ctx, udpAddr, tlsCfg, &quic.Config{
		EnableDatagrams: true,
		KeepAlivePeriod: 15 * time.Second,
	})
	if err != nil {
		_ = tr.Close()
		return nil, fmt.Errorf("direct: QUIC dial %s: %w", proxyAddr, err)
	}

	h3tr := &http3.Transport{EnableDatagrams: true}
	hconn := h3tr.NewClientConn(qconn)

	var authority string
	if proxyAddr.Addr().Is6() {
		authority = fmt.Sprintf("[%s]:%d", proxyAddr.Addr(), proxyAddr.Port())
	} else {
		authority = proxyAddr.String()
	}
	template := uritemplate.MustNew(fmt.Sprintf("https://%s/mion", authority))

	ipconn, _, err := connectip.Dial(ctx, hconn, template)
	if err != nil {
		_ = qconn.CloseWithError(0, "connect-ip failed")
		_ = tr.Close()
		return nil, fmt.Errorf("direct: CONNECT-IP dial %s: %w", proxyAddr, err)
	}

	return &DirectConn{inner: ipconn}, nil
}
