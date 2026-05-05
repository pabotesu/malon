// Package stun provides an external IP discovery function using the pion/stun
// library (RFC 5389 compliant). It sends a Binding Request to a STUN server
// and returns the XOR-MAPPED-ADDRESS from the response.
package stun

import (
	"context"
	"fmt"
	"net/netip"

	pionstun "github.com/pion/stun/v3"
)

// Query sends a STUN Binding Request to stunServer (e.g. "stun.l.google.com:19302")
// and returns the observed external address (XOR-MAPPED-ADDRESS).
// The context deadline is honoured via the underlying connection timeout.
func Query(ctx context.Context, stunServer string) (netip.AddrPort, error) {
	uri, err := pionstun.ParseURI("stun:" + stunServer)
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf("stun: parse URI: %w", err)
	}

	c, err := pionstun.DialURI(uri, &pionstun.DialConfig{})
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf("stun: dial %s: %w", stunServer, err)
	}
	defer c.Close()

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
		return netip.AddrPort{}, fmt.Errorf("stun: do: %w", err)
	}
	if doErr != nil {
		return netip.AddrPort{}, doErr
	}

	ip, ok := netip.AddrFromSlice(xorAddr.IP)
	if !ok {
		return netip.AddrPort{}, fmt.Errorf("stun: invalid IP from %s", stunServer)
	}
	return netip.AddrPortFrom(ip.Unmap(), uint16(xorAddr.Port)), nil
}
