package net

import (
	"io"
	"net"
	"fmt"
	"log"
	"bufio"
	"errors"
	"encoding/binary"
)


// SOCKS authentication methods
const (
	methNoAuth = iota
	methGSS
	methUserPass
	methNone = 0xff
)

// Address types
const (
	addrIPv4 = 0x01
	addrDomain = 0x03
	addrIPv6 = 0x04
)

// Commands
const (
	cmdConnect = 0x01
	cmdBind = 0x02
	cmdAssociate = 0x03
)

// Reply codes
const (
	repSucceeded = iota
	repGeneralFailure
	repConnectionNotAllowed
	repNetworkUnreachable
	repHostUnreachable
	repConnectionRefused
	repTTLExpired
	repCommandNotSupported
	repAddressTypeNotSupported
)

var errAddressTypeNotSupported = errors.New("SOCKS5 address type not supported")
var errCommandNotSupported = errors.New("SOCKS5 command not supported")

// Read an IPv4 or IPv6 address from an io.Reader and return it as a string
func readIP(br *bufio.Reader, len int) (string, error) {
	addr := make([]byte, len)
	_,err := io.ReadFull(br, addr)
	if err != nil {
		return "", err
	}
	return net.IP(addr).String(), nil
}

// Flush any data buffered in a bufio.Reader to a designated io.Writer.
// Used for transitioning from SOCKS negotiation to data-forwarding mode.
func bufFlush(br *bufio.Reader, w io.Writer) error {

	n := br.Buffered()
	if n == 0 {
		return nil	// nothing buffered to flush
	}

	buf := make([]byte, n)
	if _,err := io.ReadFull(br, buf); err != nil {
		return err
	}
	_,err := w.Write(buf)
	return err
}

// First flush any buffered data in the optional br to w,
// then copy data from unbuffered reader r to w untio EOF.
// Close both r and w when done.
func socksRelay(w io.WriteCloser, br *bufio.Reader, r io.ReadCloser) {
	if br != nil {
		err := bufFlush(br, w)
		if err != nil {
			log.Printf("socksRelay: "+err.Error())
		}
	}

	_,err := io.Copy(w, r)
	if err != nil {
		log.Printf("socksRelay: "+err.Error())
	}

	r.Close()
	w.Close()
}

func socks5ReadAddr(br *bufio.Reader, addrtype byte) (string, error) {

	// Read the host address
	var hostaddr string
	switch int(addrtype) {
	case addrIPv4:
		ha,err := readIP(br, net.IPv4len)
		if err != nil {
			return "", err
		}
		hostaddr = ha

	case addrIPv6:
		ha,err := readIP(br, net.IPv6len);
		if err != nil {
			return "", err
		}
		hostaddr = ha

	case addrDomain:

		// First read the 1-byte domain name length
		namelen,err := br.ReadByte()
		if err != nil {
			return "", err
		}

		// Now the domain name itself
		namebuf := make([]byte, int(namelen))
		if _,err = io.ReadFull(br, namebuf); err != nil {
			return "", err
		}
		hostaddr = string(namebuf)

	default:
		msg := fmt.Sprintf("SOCKS5: unknown address type %d", addrtype)
		return "", errors.New(msg)
	}

	// Read the port number
	var port uint16
	if err := binary.Read(br, binary.BigEndian, &port); err != nil {
		return "", err
	}

	return fmt.Sprintf("%s:%d", hostaddr, port), nil
}

type socks4req struct {
	command byte
	port uint16
	ip [4]byte
}

type socks4reply struct {
	null byte
	status byte
	port uint16
	ip [4]byte
}

type replyfun func(w io.Writer, status error, addr net.Addr) error

func socksConnect(br *bufio.Reader, client net.Conn, destaddr string,
			view View, reply replyfun) error {

	// Connect to the requested destination
	dest,err := view.Dial("tcp", destaddr, nil)

	// Reply to the client (including on connect error)
	reply(client, err, dest.LocalAddr())
	if err != nil {
		return err
	}

	// Commence forwarding raw data on the connection
	go socksRelay(client, br, dest)
	socksRelay(dest, nil, client)
	return nil
}

func socks4Reply(w io.Writer, status error, addr net.Addr) error {
	reply := socks4reply{}

	// Bind address
	if tcpaddr,ok := addr.(*net.TCPAddr); ok {
		host4 := tcpaddr.IP.To4()
		if host4 != nil {
			copy(reply.ip[:], host4)
		}
		reply.port = uint16(tcpaddr.Port)
	}

	// Status code
	if status == nil {
		reply.status = 0x5a	// request granted
	} else {
		reply.status = 0x5b	// request rejected or failed
	}

	err := binary.Write(w, binary.BigEndian, &reply)
	return err
}

func socks4Serve(br *bufio.Reader, conn net.Conn, view View) error {

	// Read the SOCKS4 request header
	req := socks4req{}
	if err := binary.Read(br, binary.BigEndian, &req); err != nil {
		return err
	}
	if _,err := br.ReadString(0); err != nil {
		return err
	}
	dstaddr := net.TCPAddr{req.ip[:], int(req.port), ""}
	dst := dstaddr.String()

	// Handle the SOCKS4a domain name extension
	if (req.ip[0] | req.ip[1] | req.ip[2]) == 0 && req.ip[3] != 0 {
		host,err := br.ReadString(0)
		if err != nil {
			return err
		}
		dst = fmt.Sprintf("%s:%d", host, req.port)
	}

	// Process the command
	var err error
	switch int(req.command) {
	case cmdConnect:
		err = socksConnect(br, conn, dst, view, socks4Reply)
	//case cmdBind:
	//	err = socksBind(br, conn, dst, view, socks4Reply)
	default:
		err = errors.New(fmt.Sprintf("SOCKS4: unknown command %d",
						req.command))
		err = socks4Reply(conn, err, nil)
	}
	return err
}

type socks5method struct {
	ver byte
	meth byte
}

type socks5req struct {
	ver byte
	cmd byte
	rsv byte
	atyp byte
}

type socks5reply struct {
	ver byte
	rep byte
	rsv byte
	atyp byte
}

func socks5Reply(w io.Writer, status error, addr net.Addr) error {

	reply := socks5reply{5,0,0,0}

	// Bind address
	var addrbuf []byte
	if tcpaddr,ok := addr.(*net.TCPAddr); ok {
		host4 := tcpaddr.IP.To4()
		host6 := tcpaddr.IP.To16()
		port := [2]byte{}
		binary.BigEndian.PutUint16(port[:], uint16(tcpaddr.Port))
		if host4 != nil {		// it's an IPv4 address
			reply.atyp = byte(addrIPv4)
			addrbuf = append(host4, port[:]...)
		} else if host6 != nil {	// it's an IPv6 address
			reply.atyp = byte(addrIPv6)
			addrbuf = append(host6, port[:]...)
		} else {			// huh???
			addr = nil
			status = errAddressTypeNotSupported
		}
	}
	if addr == nil {	// attach a null IPv4 address
		reply.atyp = addrIPv4
		addrbuf = make([]byte, 4+2)
	}

	// Reply code
	var rep int
	switch status {
	case nil:
		rep = repSucceeded
	case errAddressTypeNotSupported:
		rep = repAddressTypeNotSupported
	case errCommandNotSupported:
		rep = repCommandNotSupported
	default:
		rep = repGeneralFailure
	}
	reply.rep = byte(rep)

	// Write the reply header and address
	if err := binary.Write(w, binary.BigEndian, &reply); err != nil {
		return err
	}
	if _,err := w.Write(addrbuf); err != nil {
		return err
	}
	return nil
}

func socks5Serve(br *bufio.Reader, conn net.Conn, view View) error {

	// Read the methods list
	nmeth,err := br.ReadByte()
	if err != nil {
		return err
	}
	methods := make([]byte, nmeth)
	if _,err = io.ReadFull(br, methods); err != nil {
		return err
	}

	// Find a supported method (currently only NoAuth)
	methresp := socks5method{5, byte(methNone)}
	for i := range(methods) {
		if methods[i] == methNoAuth {
			methresp.meth = methods[i]
			break
		}
	}

	// Reply with the chosen method, if any
	if err = binary.Write(conn, binary.BigEndian, &methresp); err != nil {
		return err
	}
	if methresp.meth == byte(methNone) {
		return errors.New("SOCKS5: no supported method")
	}

	// XXX handle authentication

	// Receive client request
	req := socks5req{}
	if err = binary.Read(br, binary.BigEndian, &req); err != nil {
		return err
	}
	if req.ver != 5 {
		return errors.New("SOCKS5: wrong request version")
	}
	destaddr,err := socks5ReadAddr(br, req.atyp)
	if err != nil {
		return err
	}

	// Process the command
	log.Printf("SOCKS proxy: request %d for %s\n", req.cmd, destaddr)
	switch int(req.cmd) {
	case cmdConnect:
		err = socksConnect(br, conn, destaddr, view, socks5Reply)
	// case cmdBind: XXX
	default:
		err = errors.New(fmt.Sprintf("SOCKS: unsupported command %d",
						req.cmd))
		err = socks5Reply(conn, errCommandNotSupported, nil)
	}
	return err
}

// Service an accepted SOCKS connection from a client.
func socksServe(conn net.Conn, view View) {

	defer conn.Close()	// close client connection on any error/return

	// Get a buffered version of the connection for convenience
	br := bufio.NewReader(conn)

	// Read SOCKS version number
	ver,err := br.ReadByte()
	if err != nil {
		log.Printf("SOCKS: "+err.Error())
		return
	}

	switch ver {
	case 4:
		err = socks4Serve(br, conn, view)
	case 5:
		err = socks5Serve(br, conn, view)
	default:
		log.Printf("SOCKS: unsupported protocol version %d", ver)
	}
	if err != nil {
		log.Printf("SOCKS: "+err.Error())
		return
	}
}

// Main loop to accept and service SOCKS connections.
func socksAccept(lsock net.Listener, target View) {

	log.Printf("SOCKS: listening on %s\n", lsock.Addr().String())
	defer lsock.Close()	// close listen socket on error
	for {
		conn,err := lsock.Accept()
		if err != nil {
			log.Printf("SOCKS accept error: %s", err.Error())
			return
		}
		log.Printf("SOCKS: accept on %s from %s\n",
				conn.LocalAddr().String(),
				conn.RemoteAddr().String())
		go socksServe(conn, target)
	}
}

// Create a SOCKS server that listens and serves connections in one View,
// giving clients access to a possibly different network View.
// Because the service and target Views may be different,
// this implementation can support construction of
// SOCKS-based forwarding tunnels of all types.
//
// On success, forks off the server as a separate asynchronous goroutine.
// Close() the returned net.Listener to stop and tear down this server.
//
// XXX add auth support, etc.
func NewSocksServer(address string, listenView, targetView View) (net.Listener, error) {

	lsock,e := listenView.Listen(address, "tcp")
	if e != nil {
		return nil,e
	}

	go socksAccept(lsock, targetView)
	return lsock,nil
}

