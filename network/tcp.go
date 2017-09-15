package network

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/dedis/onet/log"
)

// a connection will return an io.EOF after readTimeout if nothing has been
// sent.
var readTimeout = 1 * time.Minute

// MaxPacketSize limits the amount of memory that is allocated before a packet
// is checked and thrown away if it's not legit. If you need more than 10MB
// packets, increase this value.
var MaxPacketSize = Size(10 * 1024 * 1024)

// NewTCPRouter returns a new Router using TCPHost as the underlying Host.
func NewTCPRouter(sid *ServerIdentity) (*Router, error) {
	h, err := NewTCPHost(sid.Address)
	if err != nil {
		return nil, err
	}
	r := NewRouter(sid, h)
	return r, nil
}

// TCPConn implements the Conn interface using plain, unencrypted TCP.
type TCPConn struct {
	// The name of the endpoint we are connected to.
	endpoint Address

	// The connection used
	conn net.Conn

	// closed indicator
	closed    bool
	closedMut sync.Mutex
	// So we only handle one receiving packet at a time
	receiveMutex sync.Mutex
	// So we only handle one sending packet at a time
	sendMutex sync.Mutex

	counterSafe
}

// NewTCPConn will open a TCPConn to the given address.
// In case of an error it returns a nil TCPConn and the error.
func NewTCPConn(addr Address) (conn *TCPConn, err error) {
	netAddr := addr.NetworkAddress()
	for i := 1; i <= MaxRetryConnect; i++ {
		var c net.Conn
		c, err = net.Dial("tcp", netAddr)
		if err == nil {
			conn = &TCPConn{
				endpoint: addr,
				conn:     c,
			}
			return
		}
		if i < MaxRetryConnect {
			time.Sleep(WaitRetry)
		}
	}
	if err == nil {
		err = ErrTimeout
	}
	return
}

// Receive get the bytes from the connection then decodes the buffer.
// It returns the Envelope containing the message,
// or EmptyEnvelope and an error if something wrong happened.
func (c *TCPConn) Receive() (env *Envelope, e error) {
	defer func() {
		if err := recover(); err != nil {
			e = fmt.Errorf("Error Received message: %v\n%s", err, log.Stack())
			env = nil
		}
	}()

	buff, err := c.receiveRaw()
	if err != nil {
		return nil, err
	}

	id, body, err := Unmarshal(buff)
	return &Envelope{
		MsgType: id,
		Msg:     body,
	}, err
}

// receiveRaw reads the size of the message, then the
// whole message. It returns the raw message as slice of bytes.
// If there is no message available, it blocks until one becomes
// available.
// In case of an error it returns a nil slice and the error.
func (c *TCPConn) receiveRaw() ([]byte, error) {
	c.receiveMutex.Lock()
	defer c.receiveMutex.Unlock()
	c.conn.SetReadDeadline(time.Now().Add(readTimeout))
	// First read the size
	var total Size
	if err := binary.Read(c.conn, globalOrder, &total); err != nil {
		return nil, handleError(err)
	}
	if total > MaxPacketSize {
		return nil, errors.New(c.endpoint.String() + " sends too big packet")
	}

	b := make([]byte, total)
	var read Size
	var buffer bytes.Buffer
	for read < total {
		// Read the size of the next packet.
		c.conn.SetReadDeadline(time.Now().Add(readTimeout))
		n, err := c.conn.Read(b)
		// Quit if there is an error.
		if err != nil {
			return nil, handleError(err)
		}
		// Append the read bytes into the buffer.
		if _, err := buffer.Write(b[:n]); err != nil {
			log.Error("Couldn't write to buffer:", err)
		}
		read += Size(n)
		b = b[n:]
	}

	// register how many bytes we read.
	c.updateRx(uint64(read))
	return buffer.Bytes(), nil
}

// Send converts the NetworkMessage into an ApplicationMessage
// and sends it using send().
// It returns an error if anything was wrong.
func (c *TCPConn) Send(msg Message) error {
	c.sendMutex.Lock()
	defer c.sendMutex.Unlock()

	b, err := Marshal(msg)
	if err != nil {
		return fmt.Errorf("Error marshaling  message: %s", err.Error())
	}
	return c.sendRaw(b)
}

// sendRaw writes the number of bytes of the message to the network then the
// whole message b in slices of size maxChunkSize.
// In case of an error it aborts and returns error.
func (c *TCPConn) sendRaw(b []byte) error {
	// First write the size
	packetSize := Size(len(b))
	if err := binary.Write(c.conn, globalOrder, packetSize); err != nil {
		return err
	}
	// Then send everything through the connection
	// Send chunk by chunk
	log.Lvl5("Sending from", c.conn.LocalAddr(), "to", c.conn.RemoteAddr())
	var sent Size
	for sent < packetSize {
		n, err := c.conn.Write(b[sent:])
		if err != nil {
			return handleError(err)
		}
		sent += Size(n)
	}
	// update stats on the connection.
	c.updateTx(uint64(packetSize))
	return nil
}

// Remote returns the name of the peer at the end point of
// the connection.
func (c *TCPConn) Remote() Address {
	return c.endpoint
}

// Local returns the local address and port.
func (c *TCPConn) Local() Address {
	return NewTCPAddress(c.conn.LocalAddr().String())
}

// Type returns PlainTCP.
func (c *TCPConn) Type() ConnType {
	return PlainTCP
}

// Close the connection.
// Returns error if it couldn't close the connection.
func (c *TCPConn) Close() error {
	c.closedMut.Lock()
	defer c.closedMut.Unlock()
	if c.closed == true {
		return ErrClosed
	}
	err := c.conn.Close()
	c.closed = true
	if err != nil {
		handleError(err)
	}
	return nil
}

// handleError translates the network-layer error to a set of errors
// used in our packages.
func handleError(err error) error {
	if strings.Contains(err.Error(), "use of closed") || strings.Contains(err.Error(), "broken pipe") {
		return ErrClosed
	} else if strings.Contains(err.Error(), "canceled") {
		return ErrCanceled
	} else if err == io.EOF || strings.Contains(err.Error(), "EOF") {
		return ErrEOF
	}

	netErr, ok := err.(net.Error)
	if !ok {
		return ErrUnknown
	}
	if netErr.Timeout() {
		return ErrTimeout
	}
	return ErrUnknown
}

// TCPListener implements the Host-interface using Tcp as a communication channel.
type TCPListener struct {
	// the underlying golang/net listener.
	listener net.Listener
	// the close channel used to indicate to the listener we want to quit.
	quit chan bool
	// quitListener is a channel to indicate to the closing function that the
	// listener has actually really quit.
	quitListener  chan bool
	listeningLock sync.Mutex
	listening     bool

	// closed tells the listen routine to return immediately if a
	// Stop() has been called.
	closed bool

	// actual listening addr which might differ from initial address in
	// case of ":0"-address.
	addr net.Addr
}

// NewTCPListener returns a TCPListener. This function binds to the given
// address.
// It returns the listener and an error if one occurred during
// the binding.
// A subsequent call to Address() gives the actual listening
// address which is different if you gave it a ":0"-address.
func NewTCPListener(addr Address) (*TCPListener, error) {
	if addr.ConnType() != PlainTCP {
		return nil, errors.New("TCPListener can't listen on non-tcp address")
	}
	t := &TCPListener{
		quit:         make(chan bool),
		quitListener: make(chan bool),
	}
	global, _ := GlobalBind(addr.NetworkAddress())
	for i := 0; i < MaxRetryConnect; i++ {
		ln, err := net.Listen("tcp", global)
		if err == nil {
			t.listener = ln
			break
		} else if i == MaxRetryConnect-1 {
			return nil, errors.New("Error opening listener: " + err.Error())
		}
		time.Sleep(WaitRetry)
	}
	t.addr = t.listener.Addr()
	return t, nil
}

// Listen starts to listen for incoming connections and calls fn for every
// connection-request it receives.
// If the connection is closed, an error will be returned.
func (t *TCPListener) Listen(fn func(Conn)) error {
	receiver := func(tc Conn) {
		go fn(tc)
	}
	return t.listen(receiver)
}

// listen is the private function that takes a function that takes a TCPConn.
// That way we can control what to do of the TCPConn before returning it to the
// function given by the user. fn is called in the same routine.
func (t *TCPListener) listen(fn func(Conn)) error {
	t.listeningLock.Lock()
	if t.closed == true {
		t.listeningLock.Unlock()
		return nil
	}
	t.listening = true
	t.listeningLock.Unlock()
	for {
		conn, err := t.listener.Accept()
		if err != nil {
			select {
			case <-t.quit:
				t.quitListener <- true
				return nil
			default:
			}
			continue
		}
		c := TCPConn{
			endpoint: NewTCPAddress(conn.RemoteAddr().String()),
			conn:     conn,
		}
		fn(&c)
	}
}

// Stop the listener. It waits till all connections are closed
// and returned from.
// If there is no listener it will return an error.
func (t *TCPListener) Stop() error {
	// lets see if we launched a listening routing
	t.listeningLock.Lock()
	defer t.listeningLock.Unlock()

	close(t.quit)

	if t.listener != nil {
		if err := t.listener.Close(); err != nil {
			if handleError(err) != ErrClosed {
				return err
			}
		}
	}
	var stop bool
	if t.listening {
		for !stop {
			select {
			case <-t.quitListener:
				stop = true
			case <-time.After(time.Millisecond * 50):
				continue
			}
		}
	}

	t.quit = make(chan bool)
	t.listening = false
	t.closed = true
	return nil
}

// Address returns the listening address.
func (t *TCPListener) Address() Address {
	t.listeningLock.Lock()
	defer t.listeningLock.Unlock()
	return NewAddress(PlainTCP, t.addr.String())
}

// Listening returns whether it's already listening.
func (t *TCPListener) Listening() bool {
	t.listeningLock.Lock()
	defer t.listeningLock.Unlock()
	return t.listening
}

// TCPHost implements the Host interface using TCP connections.
type TCPHost struct {
	addr Address
	*TCPListener
}

// NewTCPHost returns a new Host using TCP connection based type.
func NewTCPHost(addr Address) (*TCPHost, error) {
	h := &TCPHost{
		addr: addr,
	}
	var err error
	h.TCPListener, err = NewTCPListener(addr)
	return h, err
}

// Connect can only connect to PlainTCP connections.
// It will return an error if it is not a PlainTCP-connection-type.
func (t *TCPHost) Connect(si *ServerIdentity) (Conn, error) {
	addr := si.Address
	switch addr.ConnType() {
	case PlainTCP:
		c, err := NewTCPConn(addr)
		return c, err
	}
	return nil, fmt.Errorf("TCPHost %s can't handle this type of connection: %s", addr, addr.ConnType())
}

// NewTCPAddress returns a new Address that has type PlainTCP with the given
// address addr.
func NewTCPAddress(addr string) Address {
	return NewAddress(PlainTCP, addr)
}
