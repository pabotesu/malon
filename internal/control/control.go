// Package control defines the MALON peer-to-peer control message protocol.
// Messages are exchanged via the CONTROL capsule channel inside a
// RelayTunnelConn (inner mTLS stream), using JSON encoding for Phase 4.
package control

import (
	"encoding/json"
	"fmt"
)

// MsgType identifies the type of a control message.
type MsgType string

const (
	// MsgTypeCandidates carries a list of direct-path candidates from a peer.
	MsgTypeCandidates MsgType = "candidates"
)

// CandidateInfo is the wire representation of a single candidate address.
type CandidateInfo struct {
	Kind string `json:"kind"` // "embedded" or "stuned"
	Addr string `json:"addr"` // "IP:port"
}

// Message is the top-level control message envelope.
type Message struct {
	Type       MsgType         `json:"type"`
	Generation uint32          `json:"gen"`
	Candidates []CandidateInfo `json:"candidates,omitempty"`
}

// Encode serialises msg to JSON.
func Encode(msg Message) ([]byte, error) {
	data, err := json.Marshal(msg)
	if err != nil {
		return nil, fmt.Errorf("control: encode: %w", err)
	}
	return data, nil
}

// Decode deserialises a JSON-encoded control message.
func Decode(data []byte) (Message, error) {
	var msg Message
	if err := json.Unmarshal(data, &msg); err != nil {
		return Message{}, fmt.Errorf("control: decode: %w", err)
	}
	return msg, nil
}
