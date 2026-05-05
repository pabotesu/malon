// Package envelope defines the MALON framing format that wraps payloads
// sent over the shared HTTP/2 CONNECT stream between a peer and the Relay.
//
// Wire format (74-byte fixed header followed by payload):
//
//	[0]    version       uint8
//	[1]    stream_type   uint8  (StreamTypeData | StreamTypeControl)
//	[2:34] src_peer_id   [32]byte
//	[34:66] dst_peer_id  [32]byte
//	[66:70] session_id   uint32 big-endian
//	[70:74] payload_len  uint32 big-endian
//	[74:]  payload       []byte
package envelope

import (
	"encoding/binary"
	"fmt"
	"io"

	"github.com/pabotesu/malon/internal/identity"
)

const (
	Version1 = 1

	// StreamTypeData carries raw IP packets (inner mTLS encrypted).
	StreamTypeData uint8 = 0
	// StreamTypeControl carries candidate / signalling messages.
	StreamTypeControl uint8 = 1

	headerSize = 1 + 1 + 32 + 32 + 4 + 4 // 74 bytes
)

// SessionID identifies a peer-to-peer session within a shared CONNECT stream.
type SessionID uint32

// Envelope is a decoded MALON envelope.
type Envelope struct {
	Version    uint8
	StreamType uint8
	SrcPeerID  identity.PeerID
	DstPeerID  identity.PeerID
	SessionID  SessionID
	Payload    []byte
}

// Encode writes the envelope to w.
func Encode(w io.Writer, env Envelope) error {
	var hdr [headerSize]byte
	hdr[0] = env.Version
	hdr[1] = env.StreamType
	copy(hdr[2:34], env.SrcPeerID[:])
	copy(hdr[34:66], env.DstPeerID[:])
	binary.BigEndian.PutUint32(hdr[66:70], uint32(env.SessionID))
	binary.BigEndian.PutUint32(hdr[70:74], uint32(len(env.Payload)))

	if _, err := w.Write(hdr[:]); err != nil {
		return fmt.Errorf("envelope: write header: %w", err)
	}
	if len(env.Payload) > 0 {
		if _, err := w.Write(env.Payload); err != nil {
			return fmt.Errorf("envelope: write payload: %w", err)
		}
	}
	return nil
}

// Decode reads one envelope from r.
func Decode(r io.Reader) (Envelope, error) {
	var hdr [headerSize]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return Envelope{}, fmt.Errorf("envelope: read header: %w", err)
	}

	payloadLen := binary.BigEndian.Uint32(hdr[70:74])
	var payload []byte
	if payloadLen > 0 {
		payload = make([]byte, payloadLen)
		if _, err := io.ReadFull(r, payload); err != nil {
			return Envelope{}, fmt.Errorf("envelope: read payload: %w", err)
		}
	}

	var env Envelope
	env.Version = hdr[0]
	env.StreamType = hdr[1]
	copy(env.SrcPeerID[:], hdr[2:34])
	copy(env.DstPeerID[:], hdr[34:66])
	env.SessionID = SessionID(binary.BigEndian.Uint32(hdr[66:70]))
	env.Payload = payload
	return env, nil
}
