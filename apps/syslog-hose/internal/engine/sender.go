package engine

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"math/rand"
	"net"
	"strconv"
	"time"
)

// Sender writes one syslog message to the destination.
type Sender interface {
	Send(msg string) error
	Close() error
}

// NewSender builds a sender for transport "udp", "tcp" or "tls".
// TCP and TLS use RFC 6587 octet-counting framing and reconnect lazily.
// tlsConf (see TLSConfig) applies to "tls" only; nil verifies the
// receiver against the system roots. Cancelling ctx aborts in-progress
// dials (and, for streams, writes).
func NewSender(ctx context.Context, transport, host string, port int, tlsConf *tls.Config) (Sender, error) {
	addr := net.JoinHostPort(host, strconv.Itoa(port))
	switch transport {
	case "udp":
		var d net.Dialer
		conn, err := d.DialContext(ctx, "udp", addr)
		if err != nil {
			return nil, err
		}
		return &udpSender{conn: conn}, nil
	case "tcp", "tls":
		s := &streamSender{ctx: ctx, addr: addr}
		if transport == "tls" {
			if tlsConf == nil {
				tlsConf = &tls.Config{}
			}
			s.tlsConf = tlsConf
		}
		return s, nil
	default:
		return nil, fmt.Errorf("unknown transport %q", transport)
	}
}

type udpSender struct{ conn net.Conn }

func (u *udpSender) Send(msg string) error {
	_, err := u.conn.Write([]byte(msg))
	return err
}
func (u *udpSender) Close() error { return u.conn.Close() }

const (
	ioTimeout   = 5 * time.Second        // dial and per-write deadline
	backoffBase = 250 * time.Millisecond // first reconnect delay after a failure
	backoffMax  = 5 * time.Second        // reconnect delay cap
)

// streamSender handles TCP/TLS with octet-counted framing (RFC 6587 §3.4.1)
// and transparent reconnection:
//   - before each write it checks whether the receiver has hung up (FIN/RST
//     or TLS close_notify) and reconnects instead of writing into a dead
//     socket, where the first message would be silently lost;
//   - a failed write is retried once, immediately, on a fresh connection
//     with the same frame;
//   - only when that fails too does it back off, exponentially with jitter
//     (capped at backoffMax); messages during the backoff fail fast.
type streamSender struct {
	ctx     context.Context
	addr    string
	tlsConf *tls.Config // nil = plain TCP

	conn      net.Conn
	written   bool        // conn has carried at least one frame
	unwatch   func() bool // detaches the ctx watcher of conn
	failures  int
	nextRetry time.Time
	rng       *rand.Rand
}

func (s *streamSender) connect() error {
	d := net.Dialer{Timeout: ioTimeout}
	var (
		conn net.Conn
		err  error
	)
	if s.tlsConf != nil {
		td := tls.Dialer{NetDialer: &d, Config: s.tlsConf}
		conn, err = td.DialContext(s.ctx, "tcp", s.addr)
	} else {
		conn, err = d.DialContext(s.ctx, "tcp", s.addr)
	}
	if err != nil {
		return err
	}
	s.conn = conn
	s.written = false
	// a stop aborts a write blocked on a stalled receiver
	s.unwatch = context.AfterFunc(s.ctx, func() { conn.SetWriteDeadline(time.Now()) })
	return nil
}

func (s *streamSender) drop() {
	if s.conn == nil {
		return
	}
	s.unwatch()
	s.conn.Close()
	s.conn = nil
}

// backoff schedules the next reconnect attempt: base·2^failures capped at
// backoffMax, with "equal jitter" (half fixed, half random) so many jobs
// pointed at one receiver don't reconnect in lockstep.
func (s *streamSender) backoff() {
	d := backoffBase << min(s.failures, 8)
	if d > backoffMax {
		d = backoffMax
	}
	s.failures++
	if s.rng == nil {
		s.rng = rand.New(rand.NewSource(time.Now().UnixNano()))
	}
	d = d/2 + time.Duration(s.rng.Int63n(int64(d/2)+1))
	s.nextRetry = time.Now().Add(d)
}

func (s *streamSender) write(frame []byte) error {
	s.conn.SetWriteDeadline(time.Now().Add(ioTimeout))
	if err := s.ctx.Err(); err != nil {
		// cancelled before the deadline above replaced the watcher's
		return err
	}
	_, err := s.conn.Write(frame)
	return err
}

// Frame prepends the octet count per RFC 6587.
func Frame(msg string) string { return strconv.Itoa(len(msg)) + " " + msg }

func (s *streamSender) Send(msg string) error {
	frame := []byte(Frame(msg))
	if s.conn != nil && s.peerClosed() {
		s.drop()
		// a receiver that hangs up before taking a single frame would otherwise
		// get a reconnect per message
		if !s.written {
			s.backoff()
		}
	}
	if s.conn == nil {
		if wait := time.Until(s.nextRetry); wait > 0 {
			return fmt.Errorf("connection to %s down, retrying in %s", s.addr, wait.Round(time.Millisecond))
		}
		if err := s.connect(); err != nil {
			s.backoff()
			return err
		}
	}
	err := s.write(frame)
	if err == nil {
		s.failures, s.written = 0, true
		return nil
	}
	s.drop()
	if s.ctx.Err() != nil {
		return err
	}
	// one immediate reconnect, resending the same frame
	if err := s.connect(); err != nil {
		s.backoff()
		return err
	}
	if err := s.write(frame); err != nil {
		s.drop()
		s.backoff()
		return err
	}
	s.failures, s.written = 0, true
	return nil
}

// peerClosed reports whether the receiver has closed its end. Syslog
// receivers never send application data, so anything readable on the
// socket is either EOF/RST or (TLS) protocol traffic.
func (s *streamSender) peerClosed() bool {
	tc, isTLS := s.conn.(*tls.Conn)
	raw := s.conn
	if isTLS {
		raw = tc.NetConn()
	}
	switch peekConn(raw) {
	case peekOpen:
		return false
	case peekClosed:
		return true
	}
	// bytes are pending: let a short read consume them. For TLS this is a
	// close_notify alert (-> EOF) or post-handshake traffic such as session
	// tickets (-> processed, then the read times out: still open).
	var r net.Conn = raw
	if isTLS {
		r = tc
	}
	r.SetReadDeadline(time.Now().Add(20 * time.Millisecond))
	defer r.SetReadDeadline(time.Time{})
	buf := make([]byte, 4096)
	_, err := r.Read(buf)
	if err == nil {
		return false
	}
	var ne net.Error
	return !(errors.As(err, &ne) && ne.Timeout())
}

func (s *streamSender) Close() error {
	if s.conn != nil {
		s.unwatch()
		return s.conn.Close()
	}
	return nil
}
