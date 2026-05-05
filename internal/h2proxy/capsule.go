package h2proxy

// capsule.go implements minimal QUIC variable-length integer encoding
// (RFC 9000 §16) and Capsule Protocol framing (RFC 9297) for use in
// RelayTunnelConn.
//
// Capsule wire format:
//   Capsule Type   (QUIC varint, value = 0 for IP_PACKET)
//   Capsule Length (QUIC varint, byte count of payload)
//   Payload        (raw IP packet bytes)

import (
	"bufio"
	"fmt"
	"io"
	"sync"
)

const (
	capsuleTypeIPPacket uint64 = 0
	maxCapsuleLen       uint64 = 65536
)

// capsuleConn provides ReadPacket / WritePacket over any io.ReadWriter
// using Capsule Protocol framing. Safe for concurrent use.
type capsuleConn struct {
	rd    *bufio.Reader
	wr    io.Writer
	wrMu  sync.Mutex
	close func() error
}

func newCapsuleConn(r io.Reader, w io.Writer, closeFn func() error) *capsuleConn {
	return &capsuleConn{
		rd:    bufio.NewReaderSize(r, 65536),
		wr:    w,
		close: closeFn,
	}
}

// ReadPacket reads one IP_PACKET capsule from the stream into buf.
// Unknown capsule types are discarded (forward-compatibility).
func (c *capsuleConn) ReadPacket(buf []byte) (int, error) {
	for {
		ct, err := readVarint(c.rd)
		if err != nil {
			return 0, fmt.Errorf("capsule: read type varint: %w", err)
		}
		payloadLen, err := readVarint(c.rd)
		if err != nil {
			return 0, fmt.Errorf("capsule: read length varint: %w", err)
		}
		if payloadLen > maxCapsuleLen {
			return 0, fmt.Errorf("capsule: payload length %d exceeds limit %d", payloadLen, maxCapsuleLen)
		}
		if ct != capsuleTypeIPPacket {
			// Discard unknown capsule types.
			if _, err := io.CopyN(io.Discard, c.rd, int64(payloadLen)); err != nil {
				return 0, fmt.Errorf("capsule: discard type %d: %w", ct, err)
			}
			continue
		}
		if int(payloadLen) > len(buf) {
			return 0, fmt.Errorf("capsule: packet (%d B) exceeds buffer (%d B)", payloadLen, len(buf))
		}
		if _, err := io.ReadFull(c.rd, buf[:payloadLen]); err != nil {
			return 0, fmt.Errorf("capsule: read payload: %w", err)
		}
		return int(payloadLen), nil
	}
}

// WritePacket frames pkt as an IP_PACKET capsule and writes it to the stream.
func (c *capsuleConn) WritePacket(pkt []byte) error {
	hdr := appendVarint(nil, capsuleTypeIPPacket)
	hdr = appendVarint(hdr, uint64(len(pkt)))

	c.wrMu.Lock()
	defer c.wrMu.Unlock()
	if _, err := c.wr.Write(hdr); err != nil {
		return fmt.Errorf("capsule: write header: %w", err)
	}
	if _, err := c.wr.Write(pkt); err != nil {
		return fmt.Errorf("capsule: write payload: %w", err)
	}
	return nil
}

func (c *capsuleConn) Close() error {
	if c.close != nil {
		return c.close()
	}
	return nil
}

// --- QUIC varint encoding (RFC 9000 §16) ---

func readVarint(r io.ByteReader) (uint64, error) {
	b, err := r.ReadByte()
	if err != nil {
		return 0, err
	}
	prefix := b >> 6
	val := uint64(b & 0x3f)
	n := 1 << prefix // total bytes: 1, 2, 4, or 8
	for i := 1; i < n; i++ {
		b, err = r.ReadByte()
		if err != nil {
			return 0, err
		}
		val = (val << 8) | uint64(b)
	}
	return val, nil
}

func appendVarint(b []byte, v uint64) []byte {
	switch {
	case v < 64:
		return append(b, byte(v))
	case v < 16384:
		return append(b, byte(v>>8)|0x40, byte(v))
	case v < 1073741824:
		return append(b, byte(v>>24)|0x80, byte(v>>16), byte(v>>8), byte(v))
	default:
		return append(b,
			byte(v>>56)|0xc0, byte(v>>48), byte(v>>40), byte(v>>32),
			byte(v>>24), byte(v>>16), byte(v>>8), byte(v))
	}
}
