package monitor

import (
	"fmt"
	"net"
)

// NewProxy returns a new TCP proxy listening on addr:listenPort, which forwards
// connections to localhost:toPort.
func NewProxy(toPort uint16, addr string, listenPort uint16) (*TCPProxy, error) {
	ln, err := net.Listen("tcp", fmt.Sprintf("%v:%v", addr, listenPort))
	if err != nil {
		return nil, err
	}

	e := make([]*net.SRV, 1)
	e[0] = new(net.SRV)
	e[0].Target = "localhost"
	e[0].Port = toPort

	return &TCPProxy{
		Listener:  ln,
		Endpoints: e,
	}, nil
}
