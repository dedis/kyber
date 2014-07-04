package net

import (
	"net"
)

// A View represents an abstract network access viewpoint.
type View interface {

	// Connect to a destination on a named network through this view.
	// The optional net.Dialer specifies timeout and other parameters
	// to be used in the connection attempt.
	Dial(network, address string, options *net.Dialer) (net.Conn, error)

	// Listen for stream-oriented connections at a network address.
	Listen(network, address string) (net.Listener, error)

	// Listen for packet-oriented connections at a network address.
	ListenPacket(network, address string) (net.PacketConn, error)
}


type sysView struct {
}

func (*sysView) Dial(network, address string,
			dialer *net.Dialer) (net.Conn, error) {
	if dialer != nil {
		return dialer.Dial(network, address)
	} else {
		return net.Dial(network, address)
	}
}

func (*sysView) Listen(network, address string) (net.Listener, error) {
	return net.Listen(network, address)
}

func (*sysView) ListenPacket(network, address string) (net.PacketConn, error) {
	return net.ListenPacket(network, address)
}


// Base implementation of View interface represent the system's
// "native" network viewpoint.
var SystemView View = new(sysView)

