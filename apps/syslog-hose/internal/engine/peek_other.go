//go:build !(linux || darwin || freebsd || netbsd || openbsd)

package engine

import "net"

type peekResult int

const (
	peekOpen peekResult = iota
	peekClosed
	peekData
)

// peekConn has no portable non-blocking peek here; a dead peer is then only
// noticed by the failing write, which Send retries on a fresh connection.
func peekConn(net.Conn) peekResult { return peekOpen }
