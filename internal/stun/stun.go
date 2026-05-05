// Package stun provides an external IP discovery function using the pion/stun
// library (RFC 5389 compliant). It sends a Binding Request to a STUN server
// and returns the XOR-MAPPED-ADDRESS from the response.
package stun

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"time"

	pionstun "github.com/pion/stun/v3"
	"github.com/quic-go/quic-go"
)

// transportConn wraps a *quic.Transport so that pion/stun can use it as a
// net.Conn. Writes go via Transport.WriteTo (bypassing QUIC framing) and reads
// come from Transport.ReadNonQUICPacket (non-QUIC payloads buffered internally
// by quic-go). This lets us run STUN on the same UDP socket that QUIC uses,
// which is essential for NAT hole punching: the XOR-MAPPED-ADDRESS returned by
// STUN reflects the external IP:port of that exact socket.
type transportConn struct {
	tr         *quic.Transport
	remoteAddr net.Addr
	ctx        context.Context
	deadline   time.Time
}

func (c *transportConn) Read(b []byte) (int, error) {
	ctx := c.ctx
	if !c.deadline.IsZero() {
		var cancel context.CancelFunc
		ctx, cancel = context.WithDeadline(ctx, c.deadline)
		defer cancel()
	}
	n, _, err := c.tr.ReadNonQUICPacket(ctx, b)
	return n, err
}

func (c *transportConn) Write(b []byte) (int, error) {
	return c.tr.WriteTo(b, c.remoteAddr)
}

func (c *transportConn) Close() error                       { return nil } // lifetime managed by caller
func (c *transportConn) LocalAddr() net.Addr                { return c.tr.Conn.LocalAddr() }
func (c *transportConn) RemoteAddr() net.Addr               { return c.remoteAddr }
func (c *transportConn) SetDeadline(t time.Time) error      { c.deadline = t; return nil }
func (c *transportConn) SetReadDeadline(t time.Time) error  { c.deadline = t; return nil }
func (c *transportConn) SetWriteDeadline(t time.Time) error { return nil }

// QueryFromTransport sends a STUN Binding Request using the provided
// *quic.Transport's underlying UDP socket and returns the XOR-MAPPED-ADDRESS.
//
// Using the same socket as the DirectListener is mandatory: symmetric NAT
// assigns a different external port per (local-socket, remote-addr) pair, so
// discovering the external address from a separate socket gives the wrong port.
// quic.Transport.ReadNonQUICPacket is used to receive the STUN response because
// quic-go intercepts all UDP reads on the shared socket.
func QueryFromTransport(ctx context.Context, tr *quic.Transport, stunServer string) (netip.AddrPort, error) {
	host, port, err := net.SplitHostPort(stunServer)
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf("stun: invalid address %q: %w", stunServer, err)
	}

	addrs, err := net.DefaultResolver.LookupNetIP(ctx, "ip4", host)
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf("stun: resolve %s: %w", host, err)
	}
	if len(addrs) == 0 {
		return netip.AddrPort{}, fmt.Errorf("stun: no IPv4 address for %s", host)
	}
	target := net.JoinHostPort(addrs[0].String(), port)
	serverAddr, err := net.ResolveUDPAddr("udp4", target)
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf("stun: resolve addr %s: %w", target, err)
	}

	rto := 500 * time.Millisecond
	if deadline, ok := ctx.Deadline(); ok {
		if remaining := time.Until(deadline); remaining > 0 {
			if r := remaining / 3; r < rto {
				rto = r
			}
		}
	}

	conn := &transportConn{tr: tr, remoteAddr: serverAddr, ctx: ctx}
	c, err := pionstun.NewClient(conn, pionstun.WithRTO(rto))
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf("stun: new client: %w", err)
	}
	defer c.Close()

	type result struct {
		addr netip.AddrPort
		err  error
	}
	ch := make(chan result, 1)
	go func() {
		var (
			xorAddr pionstun.XORMappedAddress
			doErr   error
		)
		if err := c.Do(pionstun.MustBuild(pionstun.TransactionID, pionstun.BindingRequest), func(res pionstun.Event) {
			if res.Error != nil {
				doErr = fmt.Errorf("stun: binding request: %w", res.Error)
				return
			}
			if getErr := xorAddr.GetFrom(res.Message); getErr != nil {
				doErr = fmt.Errorf("stun: get XOR-MAPPED-ADDRESS: %w", getErr)
			}
		}); err != nil {
			ch <- result{err: fmt.Errorf("stun: do: %w", err)}
			return
		}
		if doErr != nil {
			ch <- result{err: doErr}
			return
		}
		ip, ok := netip.AddrFromSlice(xorAddr.IP)
		if !ok {
			ch <- result{err: fmt.Errorf("stun: invalid IP from %s", stunServer)}
			return
		}
		ch <- result{addr: netip.AddrPortFrom(ip.Unmap(), uint16(xorAddr.Port))}
	}()

	select {
	case <-ctx.Done():
		return netip.AddrPort{}, fmt.Errorf("stun: %w", ctx.Err())
	case r := <-ch:
		return r.addr, r.err
	}
}

// Query sends a STUN Binding Request to stunServer ("host:port") and returns
// the observed external address (XOR-MAPPED-ADDRESS).
//
// IPv4 is always used: the hostname is resolved and the first IPv4 address is
// dialled. This avoids silent failures on hosts that have an IPv6 address
// configured but no working IPv6 routing (common on VPS environments).
//
// The context deadline is respected by deriving a per-attempt RTO from the
// remaining time so that pion/stun does not retry past the deadline.
func Query(ctx context.Context, stunServer string) (netip.AddrPort, error) {
	host, port, err := net.SplitHostPort(stunServer)
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf("stun: invalid address %q: %w", stunServer, err)
	}

	// Resolve and pick the first IPv4 address to avoid IPv6 black-hole.
	addrs, err := net.DefaultResolver.LookupNetIP(ctx, "ip4", host)
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf("stun: resolve %s: %w", host, err)
	}
	if len(addrs) == 0 {
		return netip.AddrPort{}, fmt.Errorf("stun: no IPv4 address for %s", host)
	}
	target := net.JoinHostPort(addrs[0].String(), port)

	// Dial the UDP socket directly so we can control network family and pass
	// ClientOptions to pion/stun.
	udpConn, err := net.Dial("udp4", target)
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf("stun: dial %s: %w", target, err)
	}

	// Derive RTO from the context deadline so retries don't outlive it.
	rto := 500 * time.Millisecond
	if deadline, ok := ctx.Deadline(); ok {
		if remaining := time.Until(deadline); remaining > 0 {
			// Allow up to 3 attempts within the remaining time.
			if r := remaining / 3; r < rto {
				rto = r
			}
		}
	}

	c, err := pionstun.NewClient(udpConn, pionstun.WithRTO(rto))
	if err != nil {
		udpConn.Close()
		return netip.AddrPort{}, fmt.Errorf("stun: new client: %w", err)
	}
	defer c.Close() // also closes udpConn

	// Run c.Do in a goroutine so we can honour context cancellation.
	type result struct {
		addr netip.AddrPort
		err  error
	}
	ch := make(chan result, 1)
	go func() {
		var (
			xorAddr pionstun.XORMappedAddress
			doErr   error
		)
		if err := c.Do(pionstun.MustBuild(pionstun.TransactionID, pionstun.BindingRequest), func(res pionstun.Event) {
			if res.Error != nil {
				doErr = fmt.Errorf("stun: binding request: %w", res.Error)
				return
			}
			if getErr := xorAddr.GetFrom(res.Message); getErr != nil {
				doErr = fmt.Errorf("stun: get XOR-MAPPED-ADDRESS: %w", getErr)
			}
		}); err != nil {
			ch <- result{err: fmt.Errorf("stun: do: %w", err)}
			return
		}
		if doErr != nil {
			ch <- result{err: doErr}
			return
		}
		ip, ok := netip.AddrFromSlice(xorAddr.IP)
		if !ok {
			ch <- result{err: fmt.Errorf("stun: invalid IP from %s", stunServer)}
			return
		}
		ch <- result{addr: netip.AddrPortFrom(ip.Unmap(), uint16(xorAddr.Port))}
	}()

	select {
	case <-ctx.Done():
		return netip.AddrPort{}, fmt.Errorf("stun: %w", ctx.Err())
	case r := <-ch:
		return r.addr, r.err
	}
}
