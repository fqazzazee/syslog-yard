package engine

import (
	"crypto/tls"
	"fmt"
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
func NewSender(transport, host string, port int, tlsInsecure bool) (Sender, error) {
	addr := net.JoinHostPort(host, strconv.Itoa(port))
	switch transport {
	case "udp":
		conn, err := net.Dial("udp", addr)
		if err != nil {
			return nil, err
		}
		return &udpSender{conn: conn}, nil
	case "tcp", "tls":
		return &streamSender{addr: addr, useTLS: transport == "tls", insecure: tlsInsecure}, nil
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

// streamSender handles TCP/TLS with octet-counted framing (RFC 6587 §3.4.1)
// and transparent reconnection with a small backoff.
type streamSender struct {
	addr      string
	useTLS    bool
	insecure  bool
	conn      net.Conn
	nextRetry time.Time
}

func (s *streamSender) dial() error {
	if s.conn != nil {
		return nil
	}
	if time.Now().Before(s.nextRetry) {
		return fmt.Errorf("connection to %s down, retrying soon", s.addr)
	}
	d := net.Dialer{Timeout: 5 * time.Second}
	var (
		conn net.Conn
		err  error
	)
	if s.useTLS {
		conn, err = tls.DialWithDialer(&d, "tcp", s.addr, &tls.Config{InsecureSkipVerify: s.insecure})
	} else {
		conn, err = d.Dial("tcp", s.addr)
	}
	if err != nil {
		s.nextRetry = time.Now().Add(2 * time.Second)
		return err
	}
	s.conn = conn
	return nil
}

// Frame prepends the octet count per RFC 6587.
func Frame(msg string) string { return strconv.Itoa(len(msg)) + " " + msg }

func (s *streamSender) Send(msg string) error {
	if err := s.dial(); err != nil {
		return err
	}
	s.conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	if _, err := s.conn.Write([]byte(Frame(msg))); err != nil {
		s.conn.Close()
		s.conn = nil
		s.nextRetry = time.Now().Add(2 * time.Second)
		return err
	}
	return nil
}

func (s *streamSender) Close() error {
	if s.conn != nil {
		return s.conn.Close()
	}
	return nil
}
