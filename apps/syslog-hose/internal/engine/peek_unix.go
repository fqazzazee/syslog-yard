//go:build linux || darwin || freebsd || netbsd || openbsd

package engine

import (
	"net"
	"syscall"
)

type peekResult int

const (
	peekOpen   peekResult = iota // nothing to read: peer still there
	peekClosed                   // EOF (FIN) or a socket error (RST)
	peekData                     // bytes are waiting to be read
)

// peekConn does a non-blocking MSG_PEEK on the socket under c, which tells
// a half-closed peer apart from a live one without consuming anything.
func peekConn(c net.Conn) peekResult {
	sc, ok := c.(syscall.Conn)
	if !ok {
		return peekOpen
	}
	rc, err := sc.SyscallConn()
	if err != nil {
		return peekClosed
	}
	res := peekOpen
	var buf [1]byte
	err = rc.Read(func(fd uintptr) bool {
		n, _, rerr := syscall.Recvfrom(int(fd), buf[:], syscall.MSG_PEEK|syscall.MSG_DONTWAIT)
		switch {
		case rerr == syscall.EAGAIN || rerr == syscall.EWOULDBLOCK || rerr == syscall.EINTR:
			res = peekOpen
		case rerr != nil:
			res = peekClosed
		case n == 0:
			res = peekClosed
		default:
			res = peekData
		}
		return true // never wait for readability
	})
	if err != nil {
		return peekClosed
	}
	return res
}
