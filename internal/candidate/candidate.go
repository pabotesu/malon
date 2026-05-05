// Package candidate defines direct-path candidate types and collects
// embedded candidates from local network interfaces.
package candidate

import (
	"net"
	"net/netip"
)

// Kind identifies the source of a candidate address.
type Kind uint8

const (
	KindEmbedded Kind = 0 // local network interface address
	KindStuned   Kind = 1 // STUN-observed external address
)

// String returns the wire name of the Kind.
func (k Kind) String() string {
	switch k {
	case KindEmbedded:
		return "embedded"
	case KindStuned:
		return "stuned"
	default:
		return "unknown"
	}
}

// State tracks the validation lifecycle of a candidate.
type State uint8

const (
	StateIdle      State = 0
	StateProbing   State = 1
	StateValidated State = 2
	StateFailed    State = 3
	StateCooldown  State = 4
)

// Candidate is a reachability candidate for a direct path to a peer.
type Candidate struct {
	Kind       Kind
	Addr       netip.AddrPort
	Generation uint32
	State      State
}

// CollectEmbedded returns all non-loopback, non-link-local unicast IPs on
// local interfaces paired with port, as embedded candidates.
func CollectEmbedded(port uint16, generation uint32) ([]Candidate, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	var out []Candidate
	for _, iface := range ifaces {
		if iface.Flags&net.FlagLoopback != 0 || iface.Flags&net.FlagUp == 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			var ip net.IP
			switch v := a.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}
			if ip == nil || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
				continue
			}
			addr, ok := netip.AddrFromSlice(ip)
			if !ok {
				continue
			}
			addr = addr.Unmap()
			out = append(out, Candidate{
				Kind:       KindEmbedded,
				Addr:       netip.AddrPortFrom(addr, port),
				Generation: generation,
				State:      StateIdle,
			})
		}
	}
	return out, nil
}
