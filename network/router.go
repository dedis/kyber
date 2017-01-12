package network

import (
	"errors"
	"fmt"
	"sync"

	"github.com/dedis/onet/log"
)

// Router handles all networking operations such as:
//   * listening to incoming connections using a host.Listener method
//   * opening up new connections using host.Connect method
//   * dispatching incoming message using a Dispatcher
//   * dispatching outgoing message maintaining a translation
//   between ServerIdentity <-> address
//   * managing the re-connections of non-working Conn
// Most caller should use the creation function like NewTCPRouter(...),
// NewLocalRouter(...) then use the Host such as:
//
//   router.Start() // will listen for incoming Conn and block
//   router.Stop() // will stop the listening and the managing of all Conn
type Router struct {
	// id is our own ServerIdentity
	ServerIdentity *ServerIdentity
	// address is the real-actual address used by the listener.
	address Address
	// Dispatcher is used to dispatch incoming message to the right recipient
	Dispatcher
	// Host listens for new connections
	host Host
	// connections keeps track of all active connections. Because a connection
	// can be opened at the same time on both endpoints, there can be more
	// than one connection per ServerIdentityID.
	connections map[ServerIdentityID][]Conn
	sync.Mutex

	// boolean flag indicating that the router is already clos{ing,ed}.
	isClosed bool

	// wg waits for all handleConn routines to be done.
	wg sync.WaitGroup
}

// NewRouter returns a new Router attached to a ServerIdentity and the host we want to
// use.
func NewRouter(own *ServerIdentity, h Host) *Router {
	r := &Router{
		ServerIdentity: own,
		connections:    make(map[ServerIdentityID][]Conn),
		host:           h,
		Dispatcher:     NewBlockingDispatcher(),
	}
	r.address = h.Address()
	return r
}

// Start the listening routine of the underlying Host. This is a
// blocking call until r.Stop() is called.
func (r *Router) Start() {
	// Any incoming connection waits for the remote server identity
	// and will create a new handling routine.
	err := r.host.Listen(func(c Conn) {
		dst, err := r.receiveServerIdentity(c)
		if err != nil {
			log.Error("receive server identity failed:", err)
			if err := c.Close(); err != nil {
				log.Error("Couldn't close secure connection:",
					err)
			}
			return
		}
		if err := r.registerConnection(dst, c); err != nil {
			log.Lvl3(r.address, "does not accept incoming connection to", c.Remote(), "because it's closed")
			return
		}
		// start handleConn in a go routine that waits for incoming messages and
		// dispatches them.
		if err := r.launchHandleRoutine(dst, c); err != nil {
			log.Lvl3(r.address, "does not accept incoming connection to", c.Remote(), "because it's closed")
			return
		}
	})
	if err != nil {
		log.Error("Error listening:", err)
	}
}

// Stop the listening routine, and stop any routine of handling
// connections. Calling r.Start(), then r.Stop() then r.Start() again leads to
// an undefined behaviour. Callers should most of the time re-create a fresh
// Router.
func (r *Router) Stop() error {
	var err error
	err = r.host.Stop()
	r.Lock()
	// set the isClosed to true
	r.isClosed = true

	// then close all connections
	for _, arr := range r.connections {
		// take all connections to close
		for _, c := range arr {
			if err := c.Close(); err != nil {
				log.Lvl5(err)
			}
		}
	}
	// wait for all handleConn to finish
	r.Unlock()
	r.wg.Wait()

	if err != nil {
		return err
	}
	return nil
}

// Send sends to an ServerIdentity without wrapping the msg into a ProtocolMsg
func (r *Router) Send(e *ServerIdentity, msg Message) error {
	if msg == nil {
		return errors.New("Can't send nil-packet")
	}

	c := r.connection(e.ID)
	if c == nil {
		var err error
		c, err = r.connect(e)
		if err != nil {
			return err
		}
	}

	log.Lvlf4("%s sends to %s msg: %+v", r.address, e, msg)
	var err error
	err = c.Send(msg)
	if err != nil {
		log.Lvl2(r.address, "Couldn't send to", e, ":", err, "trying again")
		c, err := r.connect(e)
		if err != nil {
			return err
		}
		err = c.Send(msg)
		if err != nil {
			return err
		}
	}
	log.Lvl5("Message sent")
	return nil
}

// connect starts a new connection and launches the listener for incoming
// messages.
func (r *Router) connect(si *ServerIdentity) (Conn, error) {
	log.Lvl3(r.address, "Connecting to", si.Address)
	c, err := r.host.Connect(si)
	if err != nil {
		log.Lvl3("Could not connect to", si.Address, err)
		return nil, err
	}
	log.Lvl3(r.address, "Connected to", si.Address)
	if err := c.Send(r.ServerIdentity); err != nil {
		return nil, err
	}

	if err := r.registerConnection(si, c); err != nil {
		return nil, err
	}

	if err := r.launchHandleRoutine(si, c); err != nil {
		return nil, err
	}
	return c, nil

}

func (r *Router) removeConnection(si *ServerIdentity, c Conn) {
	r.Lock()
	defer r.Unlock()

	var toDelete = -1
	arr := r.connections[si.ID]
	for i, cc := range arr {
		if c == cc {
			toDelete = i
		}
	}

	if toDelete == -1 {
		log.Error("Remove a connection which is not registered !?")
		return
	}

	arr[toDelete] = arr[len(arr)-1]
	arr[len(arr)-1] = nil
	r.connections[si.ID] = arr[:len(arr)-1]
}

// handleConn waits for incoming messages and calls the dispatcher for
// each new message. It only quits if the connection is closed or another
// unrecoverable error in the connection appears.
func (r *Router) handleConn(remote *ServerIdentity, c Conn) {
	defer func() {
		// Clean up the connection by making sure it's closed.
		if err := c.Close(); err != nil {
			log.Lvl5(r.address, "having error closing conn to", remote.Address, ":", err)
		}
		r.wg.Done()
		r.removeConnection(remote, c)
	}()
	address := c.Remote()
	log.Lvl3(r.address, "Handling new connection to", remote.Address)
	for {
		packet, err := c.Receive()

		if r.Closed() {
			return
		}

		if err != nil {
			if err == ErrTimeout {
				log.Lvlf5("%s drops %s connection: timeout", r.ServerIdentity.Address, remote.Address)
				return
			}

			if err == ErrClosed || err == ErrEOF {
				// Connection got closed.
				log.Lvlf5("%s drops %s connection: closed", r.ServerIdentity.Address, remote.Address)
				return
			}
			// Temporary error, continue.
			log.Lvl3(r.ServerIdentity, "Error with connection", address, "=>", err)
			continue
		}

		packet.ServerIdentity = remote

		if err := r.Dispatch(&packet); err != nil {
			log.Lvl3("Error dispatching:", err)
		}

	}
}

// connection returns the first connection associated with this ServerIdentity.
// If no connection is found, it returns nil.
func (r *Router) connection(sid ServerIdentityID) Conn {
	r.Lock()
	defer r.Unlock()
	arr := r.connections[sid]
	if len(arr) == 0 {
		return nil
	}
	return arr[0]
}

// registerConnection registers a ServerIdentity for a new connection, mapped with the
// real physical address of the connection and the connection itself.
// It uses the networkLock mutex.
func (r *Router) registerConnection(remote *ServerIdentity, c Conn) error {
	log.Lvl4(r.address, "Registers", remote.Address)
	r.Lock()
	defer r.Unlock()
	if r.isClosed {
		return ErrClosed
	}
	_, okc := r.connections[remote.ID]
	if okc {
		log.Lvl5("Connection already registered. Appending new connection to same identity.")
	}
	r.connections[remote.ID] = append(r.connections[remote.ID], c)
	return nil
}

func (r *Router) launchHandleRoutine(dst *ServerIdentity, c Conn) error {
	r.Lock()
	defer r.Unlock()
	if r.isClosed {
		return ErrClosed
	}
	r.wg.Add(1)
	go r.handleConn(dst, c)
	return nil
}

// Closed returns true if the router is closed (or is closing). For a router
// to be closed means that a call to Stop() must have been made.
func (r *Router) Closed() bool {
	r.Lock()
	defer r.Unlock()
	return r.isClosed
}

// Tx implements monitor/CounterIO
// It returns the Tx for all connections managed by this router
func (r *Router) Tx() uint64 {
	r.Lock()
	defer r.Unlock()
	var tx uint64
	for _, arr := range r.connections {
		for _, c := range arr {
			tx += c.Tx()
		}
	}
	return tx
}

// Rx implements monitor/CounterIO
// It returns the Rx for all connections managed by this router
func (r *Router) Rx() uint64 {
	r.Lock()
	defer r.Unlock()
	var rx uint64
	for _, arr := range r.connections {
		for _, c := range arr {
			rx += c.Rx()
		}
	}
	return rx
}

// Listening returns true if this router is started.
func (r *Router) Listening() bool {
	return r.host.Listening()
}

// receiveServerIdentity takes a fresh new conn issued by the listener and
// wait for the server identities of the remote party. It returns
// the ServerIdentity of the remote party and register the connection.
func (r *Router) receiveServerIdentity(c Conn) (*ServerIdentity, error) {
	// Receive the other ServerIdentity
	nm, err := c.Receive()
	if err != nil {
		return nil, fmt.Errorf("Error while receiving ServerIdentity during negotiation %s", err)
	}
	// Check if it is correct
	if nm.MsgType != ServerIdentityType {
		return nil, fmt.Errorf("Received wrong type during negotiation %s", nm.MsgType.String())
	}
	// Set the ServerIdentity for this connection
	dst := nm.Msg.(*ServerIdentity)

	if err != nil {
		return nil, err
	}
	log.Lvl4(r.address, "Identity received from", dst.Address)
	return dst, nil
}
