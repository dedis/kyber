package network

// Conn represents any communication between two hosts.
type Conn interface {
	// Send a message through the connection.
	// obj should be a POINTER to the actual struct to send, or an interface.
	// It should not be a Golang type.
	// Returns the number of bytes sent and an error if any.
	Send(Message) (uint64, error)
	// Receive any message through the connection. It is a blocking call that
	// returns either when a message arrived or when Close() has been called, or
	// when a network error occurred.
	Receive() (*Envelope, error)
	// Close will close the connection. Implementations must take care that
	// Close() makes Receive() returns with an error, and any subsequent Send()
	// will return with an error. Calling Close() on a closed Conn will return
	// ErrClosed.
	Close() error

	// Type returns the type of this connection.
	Type() ConnType
	// Gives the address of the remote endpoint.
	Remote() Address
	// Returns the local address and port.
	Local() Address
	// Tx returns how many bytes this connection has written
	Tx() uint64
	// Rx returns how many bytes this connection has read
	Rx() uint64
}

// Listener is responsible for listening for incoming Conns on a particular
// address. It can only accept one type of incoming Conn.
type Listener interface {
	// Listen for incoming connections.
	// Each time there is an incoming Conn, it calls the given
	// function in a go routine with the incoming Conn as parameter.
	// The call is blocking. If this listener is already Listening, Listen
	// should return an error.
	Listen(func(Conn)) error
	// Stop the listening. Implementations must take care of making
	// Stop() a blocking call. Stop() should return when the Listener really
	// has stopped listening, i.e. the call to Listen has returned. Calling twice
	// Stop() should return an error ErrClosed on the second call.
	Stop() error

	// A complete address including the type this listener is listening
	// to.
	Address() Address

	// Returns whether this listener is actually listening or not. This
	// function is mainly useful for tests where we need to make sure the
	// listening routine is started.
	Listening() bool
}

// Host listens for a specific type of Conn and can Connect to specific types
// of Conn. It is used by the Router so the router can manage connections
// while being oblivious to which type of connections it's handling.
type Host interface {
	Listener

	Connect(si *ServerIdentity) (Conn, error)
}
