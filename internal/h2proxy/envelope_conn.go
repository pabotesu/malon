package h2proxy

import (
	"io"
	"net"
	"os"
	"sync"
	"time"

	"github.com/pabotesu/malon/internal/envelope"
	"github.com/pabotesu/malon/internal/identity"
)

// EnvelopeNetConn implements net.Conn for a single peer session routed
// through InternalProxy's shared HTTP/2 CONNECT stream.
//
// Write wraps bytes in a DATA Envelope and sends via the shared stream.
// Read receives bytes dispatched by InternalProxy's readLoop via recvCh.
// Leftover bytes that don't fit into the caller's buffer are held in readBuf.
type EnvelopeNetConn struct {
	proxy     *InternalProxy
	sessionID envelope.SessionID
	peerID    identity.PeerID // remote peer (destination)

	recvCh  <-chan []byte
	readBuf []byte // leftover from previous Read call

	mu           sync.Mutex
	readDeadline time.Time
}

var _ net.Conn = (*EnvelopeNetConn)(nil)

// Read reads data from recvCh, draining readBuf first if non-empty.
// If a read deadline is set and it passes, os.ErrDeadlineExceeded is returned.
// When recvCh is closed (connection gone), io.EOF is returned.
func (c *EnvelopeNetConn) Read(b []byte) (int, error) {
	// Drain leftover buffer first.
	if len(c.readBuf) > 0 {
		n := copy(b, c.readBuf)
		c.readBuf = c.readBuf[n:]
		return n, nil
	}

	c.mu.Lock()
	deadline := c.readDeadline
	c.mu.Unlock()

	// A nil channel in a select blocks forever — correct behaviour when no deadline.
	var timeout <-chan time.Time
	if !deadline.IsZero() {
		d := time.Until(deadline)
		if d <= 0 {
			return 0, os.ErrDeadlineExceeded
		}
		t := time.NewTimer(d)
		defer t.Stop()
		timeout = t.C
	}

	select {
	case data, ok := <-c.recvCh:
		if !ok {
			return 0, io.EOF
		}
		n := copy(b, data)
		if n < len(data) {
			// Save the rest for the next Read call.
			c.readBuf = append(c.readBuf[:0], data[n:]...)
		}
		return n, nil
	case <-timeout:
		return 0, os.ErrDeadlineExceeded
	}
}

// Write sends b as a DATA Envelope to the remote peer via InternalProxy.
func (c *EnvelopeNetConn) Write(b []byte) (int, error) {
	env := envelope.Envelope{
		Version:    envelope.Version1,
		StreamType: envelope.StreamTypeData,
		SrcPeerID:  c.proxy.selfID,
		DstPeerID:  c.peerID,
		SessionID:  c.sessionID,
		Payload:    b,
	}
	if err := c.proxy.writeEnvelope(env); err != nil {
		return 0, err
	}
	return len(b), nil
}

// Close removes this session from InternalProxy, causing future Read calls
// to return io.EOF.
func (c *EnvelopeNetConn) Close() error {
	c.proxy.removeSession(c.sessionID)
	return nil
}

func (c *EnvelopeNetConn) LocalAddr() net.Addr  { return relayAddr{} }
func (c *EnvelopeNetConn) RemoteAddr() net.Addr { return relayAddr{} }

// SetDeadline sets the read deadline (write deadline is not implemented).
func (c *EnvelopeNetConn) SetDeadline(t time.Time) error {
	return c.SetReadDeadline(t)
}

// SetReadDeadline sets the deadline for future Read calls.
func (c *EnvelopeNetConn) SetReadDeadline(t time.Time) error {
	c.mu.Lock()
	c.readDeadline = t
	c.mu.Unlock()
	return nil
}

// SetWriteDeadline is a no-op. Writes are serialised through InternalProxy's
// mutex and are expected to be fast.
func (c *EnvelopeNetConn) SetWriteDeadline(_ time.Time) error { return nil }

// PeerID returns the remote peer's identity.
func (c *EnvelopeNetConn) PeerID() identity.PeerID { return c.peerID }

// relayAddr is a stub net.Addr used for LocalAddr / RemoteAddr.
type relayAddr struct{}

func (relayAddr) Network() string { return "relay" }
func (relayAddr) String() string  { return "relay" }
