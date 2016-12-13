package network

import (
	"net"
	"regexp"
	"strconv"
	"strings"
)

// ConnType represents the type of a Connection.
// The supported types are defined as constants of type ConnType.
type ConnType string

// Address contains the ConnType and the actual network address. It is used to connect
// to a remote host with a Conn and to listen by a Listener.
// A network address holds an IP address and the port number joined
// by a colon.
// It doesn't support IPv6 yet.
type Address string

const (
	// PlainTCP is an unencrypted TCP connection.
	PlainTCP ConnType = "tcp"
	// TLS is a TLS encrypted connection over TCP.
	TLS = "tls"
	// PURB is a PURB encryption connection over TCP.
	PURB = "purb"
	// Local is a channel based connection type.
	Local = "local"
	// InvalidConnType is an invalid connection type.
	InvalidConnType = "wrong"
)

// typeAddressSep is the separator between the type of the connection and the actual
// IP address.
const typeAddressSep = "://"

// connType converts a string to a ConnType. In case of failure,
// it returns InvalidConnType.
func connType(t string) ConnType {
	ct := ConnType(t)
	types := []ConnType{PlainTCP, TLS, PURB, Local}
	for _, t := range types {
		if t == ct {
			return ct
		}
	}
	return InvalidConnType
}

// ConnType returns the connection type from the address.
// It returns InvalidConnType if the address is not valid or if the
// connection type is not known.
func (a Address) ConnType() ConnType {
	if !a.Valid() {
		return InvalidConnType
	}
	vals := strings.Split(string(a), typeAddressSep)
	return connType(vals[0])
}

// NetworkAddress returns the network address part of the address, which is
// the IP address and the port joined by a colon.
// It returns an empty string if the a.Valid() returns false.
func (a Address) NetworkAddress() string {
	if !a.Valid() {
		return ""
	}
	vals := strings.Split(string(a), typeAddressSep)
	return vals[1]
}

// Valid returns true if the address is well formed or false otherwise.
// An address is well formed if it is of the form: ConnType://NetworkAddress.
// ConnType must be one of the constants defined in this file,
// NetworkAddress must contain the IP address + Port number.
// The IP address is validated by net.ParseIP & the port must be included in the
// range [0;65536].
// Ex. tls:192.168.1.10:5678
func (a Address) Valid() bool {
	vals := strings.Split(string(a), typeAddressSep)
	if len(vals) != 2 {
		return false
	}
	if connType(vals[0]) == InvalidConnType {
		return false
	}

	ip, port, e := net.SplitHostPort(vals[1])
	if e != nil {
		return false
	}

	p, err := strconv.Atoi(port)
	if err != nil || p < 0 || p > 65535 {
		return false
	}

	if ip == "localhost" {
		// localhost is not recognized by net.ParseIP ?
		return true
	} else if net.ParseIP(ip) == nil {
		return false
	}
	return true
}

// String returns the address as a string.
func (a Address) String() string {
	return string(a)
}

// Host returns the host part of the address.
// ex: "tcp://127.0.0.1:2000" => "127.0.0.1"
// In case of an error, it returns an empty string.
func (a Address) Host() string {
	na := a.NetworkAddress()
	if na == "" {
		return ""
	}
	h, _, e := net.SplitHostPort(a.NetworkAddress())
	if e != nil {
		return ""
	}
	// IPv6 unspecified address has to be in brackets.
	if h == "::" {
		h = "[::]"
	}
	return h
}

// Port will return the port part of the Address. In the
// case of an invalid address or an invalid port, it
// will return "".
func (a Address) Port() string {
	na := a.NetworkAddress()
	if na == "" {
		return ""
	}
	_, p, e := net.SplitHostPort(na)
	if e != nil {
		return ""
	}
	return p

}

// Public returns true if the address is a public and valid one
// or false otherwise.
// Specifically it checks if it is a private address by checking
// 192.168.**,10.***,127.***,172.16-31.**,169.254.**
func (a Address) Public() bool {
	private, err := regexp.MatchString("(^127\\.)|(^10\\.)|"+
		"(^172\\.1[6-9]\\.)|(^172\\.2[0-9]\\.)|"+
		"(^172\\.3[0-1]\\.)|(^192\\.168\\.)|(^169\\.254)|"+
		"(^\\[::\\])", a.NetworkAddress())
	if err != nil {
		return false
	}
	return !private && a.Valid()
}

// NewAddress takes a connection type and the raw address. It returns a
// correctly formatted address, which will be of type t.
// It doesn't do any checking of ConnType or network.
func NewAddress(t ConnType, network string) Address {
	return Address(string(t) + typeAddressSep + network)
}
