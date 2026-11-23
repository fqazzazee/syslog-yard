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
// UDP also connects on first send and re-resolves the destination while
// running, so a receiver that is late or changes address is picked up.
// tlsConf (see TLSConfig) applies to "tls" only; nil verifies the
// receiver against the system roots. Cancelling ctx aborts in-progress
// dials (and, for streams, writes).
func NewSender(ctx context.Context, transport, host string, port int, tlsConf *tls.Config) (Sender, error) {
	addr := net.JoinHostPort(host, strconv.Itoa(port))
	switch transport {
	case "udp":
		return &udpSender{ctx: ctx, addr: addr, dial: dialUDP}, nil
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

const (
	udpRefresh        = 30 * time.Second // how often a live socket re-resolves
	udpRefreshTimeout = time.Second      // limit on a lookup while a socket works
	udpRedialMin      = time.Second      // minimum gap between dial attempts on failure
)

// udpSender keeps a connected socket to the current address of its
// destination. A failed refresh keeps the socket it has.
type udpSender struct {
	ctx      context.Context
	addr     string
	dial     func(ctx context.Context, addr string) (net.Conn, error)
	conn     net.Conn
	dialedAt time.Time // last dial attempt
}

func dialUDP(ctx context.Context, addr string) (net.Conn, error) {
	var d net.Dialer
	return d.DialContext(ctx, "udp", addr)
}

// redial resolves the destination again and moves to a new socket only if
// the address changed, so the source port stays stable otherwise.
func (u *udpSender) redial(timeout time.Duration) error {
	ctx, cancel := context.WithTimeout(u.ctx, timeout)
	defer cancel()
	u.dialedAt = time.Now()
	conn, err := u.dial(ctx, u.addr)
	if err != nil {
		return err
	}
	if u.conn != nil {
		if conn.RemoteAddr().String() == u.conn.RemoteAddr().String() {
			conn.Close()
			return nil
		}
		u.conn.Close()
	}
	u.conn = conn
	return nil
}

func (u *udpSender) Send(msg string) error {
	if u.conn == nil {
		if wait := udpRedialMin - time.Since(u.dialedAt); !u.dialedAt.IsZero() && wait > 0 {
			return fmt.Errorf("destination %s unavailable, retrying in %s", u.addr, wait.Round(time.Millisecond))
		}
		if err := u.redial(ioTimeout); err != nil {
			return err
		}
	} else if time.Since(u.dialedAt) >= udpRefresh {
		_ = u.redial(udpRefreshTimeout)
	}
	_, err := u.conn.Write([]byte(msg))
	if err == nil || u.ctx.Err() != nil || time.Since(u.dialedAt) < udpRedialMin {
		return err
	}
	if u.redial(udpRefreshTimeout) != nil {
		return err
	}
	_, err = u.conn.Write([]byte(msg))
	return err
}

func (u *udpSender) Close() error {
	if u.conn == nil {
		return nil
	}
	return u.conn.Close()
}

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
