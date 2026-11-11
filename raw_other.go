//go:build !unix

package fasth2

import "syscall"

// Не на unix читатель всегда работает через net.Conn.Read.
func (c *conn) serveRawIfPossible() bool { return false }

func shutdownRaw(rc syscall.RawConn) {}
