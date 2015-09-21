// Copyright 2013 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ssh

import (
	"fmt"
	"net"
)

// OpenChannelError is returned if the other side rejects an
// OpenChannel request.
type OpenChannelError struct {
	Reason  RejectionReason
	Message string
}

func (e *OpenChannelError) Error() string {
	return fmt.Sprintf("ssh: rejected: %s (%s)", e.Reason, e.Message)
}

// ConnMetadata holds metadata for the connection.
type ConnMetadata interface {
	// User returns the user ID for this connection.
	// It is empty if no authentication is used.
	User() string

	// SessionID returns the sesson hash, also denoted by H.
	SessionID() []byte

	// ClientVersion returns the client's version string as hashed
	// into the session ID.
	ClientVersion() []byte

	// ServerVersion returns the server's version string as hashed
	// into the session ID.
	ServerVersion() []byte

	// RemoteAddr returns the remote address for this connection.
	RemoteAddr() net.Addr

	// LocalAddr returns the local address for this connection.
	LocalAddr() net.Addr
}

// sshconn provides net.Conn metadata, but disallows direct reads and
// writes.
type sshConn struct {
	conn net.Conn

	user          string
	sessionID     []byte
	clientVersion []byte
	serverVersion []byte
}

func dup(src []byte) []byte {
	dst := make([]byte, len(src))
	copy(dst, src)
	return dst
}

func (c *sshConn) User() string {
	return c.user
}

func (c *sshConn) RemoteAddr() net.Addr {
	return c.conn.RemoteAddr()
}

func (c *sshConn) Close() error {
	return c.conn.Close()
}

func (c *sshConn) LocalAddr() net.Addr {
	return c.conn.LocalAddr()
}

func (c *sshConn) SessionID() []byte {
	return dup(c.sessionID)
}

func (c *sshConn) ClientVersion() []byte {
	return dup(c.clientVersion)
}

func (c *sshConn) ServerVersion() []byte {
	return dup(c.serverVersion)
}
