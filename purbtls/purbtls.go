//purbtls is a simple TLS like protocol for encrypted communication.
//Assumes that the client has a public key for the server at the beggining of
//the protocol.

/* Protocol overview:
* Client already has public key and suite.
* Client generates a clientHelloPurb that contains required session info:
	*
	*
	*
* Server then replies with a serverHelloPurb that contains the following:
	*
	*
	*
	* Then shared key is generated (ECDH probably)


	Can purbs be simplified, because we know the message will always be with
	one key to one recipient?
	What is lost if you do this?
	PURB for sinle recipient could just be
	[elligator key][encrypted sym key][encrypted message]
	Can we authenticate encrypted sym key?

	Ignores why the server can trust the client?


	Only need 1 round trip.
*/
package purbtls

//Constants for suites.
//const {}
type Config struct {
	//Needed fields
//List of public key suites to use
//Server public key. known by client
	//Server Private key. known by server

}
//listener structure taken from golang tls implementation
type listener struct {
	net.Listener,
	config *Config
}

//Possibly use a connection, for all functions.
type PurbConn struct {
	con net.Connection
}

//What functions will be needed
//Two phases
//Handshake
//General writing.

//listener structure taken from golang tls implementation
func NewListener(inner net.Listener, config * Config) net.Listener {
	l := new(listener)
	l.Listener = inner
	l.config = config
	return l
}

func (l *listener) Accept() (c net.Conn, err error) {
	c, err = l.Listener.Accept()
	if err != nil {
		return
	}
	c = Server(c, l.config)
	return
}
func Server(c net.Conn, conf *Config) *PurbConn {
	//Handles handshake and returns a connection that is ready
	//to read/Write.
}
func Client(c net.Conn, conf *Config) *PurbConn {
	//Handles handshake and returns a connection that is ready
	//to read/Write.
}
//Terminology for functions is from tls go implementation.
//Listen for the server. Creates a connection and listens.Config
//Probably Listen(network, laddr string, cnf *Config);

//For client a dial(conn net.conn, cnf *Config)

//General use is set up Config, then call either Dial(), or Listen(),


func Listen(network, address string, conf *Config) (net.Listener, error) {

	listen, err := net.Listen(network, address)
	if err != nil {
		fmt.Print(err)
	}
	return NewListener(listen, conf), nil
}

//Dial creates a connection to a server using purbtls negotiation.
//Returns err
func Dial(network, address string, conf *Config) (*PurbConn, error) {
	pconn := PurbConn
	conn, err := net.Dial("tcp", "localhost:8080")
	if err != nil {
		fmt.Println(err)
		return nil, err
	}

	O
	return Client(conn, conf)

}


func (conn *PurbConn) Write(data []byte) error {

}

func (conn *PurbConn) Read(data []byte) ([]byte, error) {

}
