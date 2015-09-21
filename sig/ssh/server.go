// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ssh

import ()

// The Permissions type holds fine-grained permissions that are
// specific to a user or a specific authentication method for a
// user. Permissions, except for "source-address", must be enforced in
// the server application layer, after successful authentication. The
// Permissions are passed on in ServerConn so a server implementation
// can honor them.
type Permissions struct {
	// Critical options restrict default permissions. Common
	// restrictions are "source-address" and "force-command". If
	// the server cannot enforce the restriction, or does not
	// recognize it, the user should not authenticate.
	CriticalOptions map[string]string

	// Extensions are extra functionality that the server may
	// offer on authenticated connections. Common extensions are
	// "permit-agent-forwarding", "permit-X11-forwarding". Lack of
	// support for an extension does not preclude authenticating a
	// user.
	Extensions map[string]string
}
