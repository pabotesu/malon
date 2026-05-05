// Package stun implements a minimal RFC 5389 STUN Binding Request client.
// Only Binding Request / XOR-MAPPED-ADDRESS is supported, which is sufficient
// for external IP discovery (stuned candidate collection).
package stun

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"time"
)

const (
	stunMagicCookie     uint32 = 0x2112A442
	stunBindingRequest  uint16 = 0x0001
	stunBindingResponse uint16 = 0x0101
	attrXORMappedAddr   uint16 = 0x0020
)

// Query sends a STUN Binding Request to stunServer ("host:port") and returns
// the XOR-MAPPED-ADDRESS from the response.
func Query(ctx context.Context, stunServer string) (netip.AddrPort, error) {
	serverAddr, err := net.ResolveUDPAddr("udp", stunServer)
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf("stun: resolve %s: %w", stunServer, err)
	}
	conn, err := net.ListenUDP("udp", nil)
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf("stun: listen UDP: %w", err)
	}
	defer conn.Close()

	deadline, ok := ctx.Deadline()
	if !ok {
		deadline = time.Now().Add(5 * time.Second)
	}
	if err := conn.SetDeadline(deadline); err != nil {
		return netip.AddrPort{}, fmt.Errorf("stun: set deadline: %w", err)
	}

	var txID [12]byte
	if _, err := rand.Read(txID[:]); err != nil {
		return netip.AddrPort{}, fmt.Errorf("stun: generate txID: %w", err)
	}
	req := make([]byte, 20)
	binary.BigEndian.PutUint16(req[0:2], stunBindingRequest)
	binary.BigEndian.PutUint16(req[2:4], 0) // no attributes
	binary.BigEndian.PutUint32(req[4:8], stunMagicCookie)
	copy(req[8:20], txID[:])

	if _, err := conn.WriteToUDP(req, serverAddr); err != nil {
		return netip.AddrPort{}, fmt.Errorf("stun: send: %w", err)
	}

	buf := make([]byte, 512)
	n, _, err := conn.ReadFromUDP(buf)
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf("stun: recv: %w", err)
	}
	resp := buf[:n]

	if len(resp) < 20 {
		return netip.AddrPort{}, fmt.Errorf("stun: response too short (%d bytes)", n)
	}
	if binary.BigEndian.Uint16(resp[0:2]) != stunBindingResponse {
		return netip.AddrPort{}, fmt.Errorf("stun: unexpected msg type 0x%04x", binary.BigEndian.Uint16(resp[0:2]))
	}
	attrLen := int(binary.BigEndian.Uint16(resp[2:4]))
	if 20+attrLen > len(resp) {
		return netip.AddrPort{}, fmt.Errorf("stun: truncated response")
	}
	return parseXORMappedAddr(resp[20:20+attrLen], txID)
}

func parseXORMappedAddr(attrs []byte, txID [12]byte) (netip.AddrPort, error) {
	for len(attrs) >= 4 {
		aType := binary.BigEndian.Uint16(attrs[0:2])
		aLen := int(binary.BigEndian.Uint16(attrs[2:4]))
		if 4+aLen > len(attrs) {
			break
		}
		val := attrs[4 : 4+aLen]
		if aType == attrXORMappedAddr && len(val) >= 4 {
			family := binary.BigEndian.Uint16(val[0:2])
			xPort := binary.BigEndian.Uint16(val[2:4])
			port := xPort ^ uint16(stunMagicCookie>>16)
			switch family {
			case 0x0001: // IPv4
				if len(val) < 8 {
					break
				}
				xIP := binary.BigEndian.Uint32(val[4:8])
				ipRaw := xIP ^ stunMagicCookie
				ip := netip.AddrFrom4([4]byte{
					byte(ipRaw >> 24), byte(ipRaw >> 16), byte(ipRaw >> 8), byte(ipRaw),
				})
				return netip.AddrPortFrom(ip, port), nil
			case 0x0002: // IPv6
				if len(val) < 20 {
					break
				}
				var raw [16]byte
				copy(raw[:], val[4:20])
				raw[0] ^= byte((stunMagicCookie >> 24) & 0xff)
				raw[1] ^= byte((stunMagicCookie >> 16) & 0xff)
				raw[2] ^= byte((stunMagicCookie >> 8) & 0xff)
				raw[3] ^= byte(stunMagicCookie & 0xff)
				for i := 0; i < 12; i++ {
					raw[4+i] ^= txID[i]
				}
				return netip.AddrPortFrom(netip.AddrFrom16(raw), port), nil
			}
		}
		padded := (aLen + 3) &^ 3
		if 4+padded > len(attrs) {
			break
		}
		attrs = attrs[4+padded:]
	}
	return netip.AddrPort{}, fmt.Errorf("stun: no XOR-MAPPED-ADDRESS found")
}
