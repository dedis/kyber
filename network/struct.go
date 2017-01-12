package network

import (
	"bytes"
	"errors"
	"strings"
	"sync"
	"time"

	"github.com/dedis/crypto/abstract"
	"github.com/dedis/onet/crypto"
	"github.com/dedis/onet/log"
	"github.com/dedis/protobuf"
	"github.com/satori/go.uuid"
)

// MaxRetryConnect defines how many times we should try to connect.
const MaxRetryConnect = 5

// MaxIdentityExchange is the timeout for an identityExchange.
const MaxIdentityExchange = 5 * time.Second

// WaitRetry is the timeout on connection-setups.
const WaitRetry = 20 * time.Millisecond

// The various errors you can have
// XXX not working as expected, often falls on errunknown

// ErrClosed is when a connection has been closed.
var ErrClosed = errors.New("Connection Closed")

// ErrEOF is when the connection sends an EOF signal (mostly because it has
// been shut down).
var ErrEOF = errors.New("EOF")

// ErrCanceled means something went wrong in the sending or receiving part.
var ErrCanceled = errors.New("Operation Canceled")

// ErrTimeout is raised if the timeout has been reached.
var ErrTimeout = errors.New("Timeout Error")

// ErrUnknown is an unknown error.
var ErrUnknown = errors.New("Unknown Error")

// Size is a type to reprensent the size that is sent before every packet to
// correctly decode it.
type Size uint32

// Envelope is a container for any Message received through the network that
// contains the Message itself as well as some metadata such as the type and the
// sender. This is created by the network stack upon reception and is never
// transmitted.
type Envelope struct {
	// The ServerIdentity of the remote peer we are talking to.
	// Basically, this means that when you open a new connection to someone, and
	// / or listens to incoming connections, the network library will already
	// make some exchange between the two communicants so each knows the
	// ServerIdentity of the others.
	ServerIdentity *ServerIdentity
	// What kind of msg do we have
	MsgType MessageTypeID
	// A *pointer* to the underlying message
	Msg Message
	// which constructors are used
	Constructors protobuf.Constructors
	// possible error during unmarshalling so that upper layer can know it
	err error
}

// ServerIdentity is used to represent a Conode in the whole internet.
// It's based on a public key, and there can be one or more addresses to contact it.
type ServerIdentity struct {
	// This is the public key of that ServerIdentity
	Public abstract.Point
	// The ServerIdentityID corresponding to that public key
	ID ServerIdentityID
	// A slice of addresses of where that Id might be found
	Address Address
	// Description of the server
	Description string
}

// ServerIdentityID uniquely identifies an ServerIdentity struct
type ServerIdentityID uuid.UUID

// Equal returns true if both ServerIdentityID are equal or false otherwise.
func (eid ServerIdentityID) Equal(other ServerIdentityID) bool {
	return uuid.Equal(uuid.UUID(eid), uuid.UUID(other))
}

func (si *ServerIdentity) String() string {
	return si.Address.String()
}

// ServerIdentityType can be used to recognise an ServerIdentity-message
var ServerIdentityType = RegisterMessage(ServerIdentity{})

// ServerIdentityToml is the struct that can be marshalled into a toml file
type ServerIdentityToml struct {
	Public  string
	Address Address
}

// NewServerIdentity creates a new ServerIdentity based on a public key and with a slice
// of IP-addresses where to find that entity. The Id is based on a
// version5-UUID which can include a URL that is based on it's public key.
func NewServerIdentity(public abstract.Point, address Address) *ServerIdentity {
	url := NamespaceURL + "id/" + public.String()
	return &ServerIdentity{
		Public:  public,
		Address: address,
		ID:      ServerIdentityID(uuid.NewV5(uuid.NamespaceURL, url)),
	}
}

// Equal tests on same public key
func (si *ServerIdentity) Equal(e2 *ServerIdentity) bool {
	return si.Public.Equal(e2.Public)
}

// Toml converts an ServerIdentity to a Toml-structure
func (si *ServerIdentity) Toml(suite abstract.Suite) *ServerIdentityToml {
	var buf bytes.Buffer
	if err := crypto.Write64Pub(suite, &buf, si.Public); err != nil {
		log.Error("Error while writing public key:", err)
	}
	return &ServerIdentityToml{
		Address: si.Address,
		Public:  buf.String(),
	}
}

// ServerIdentity converts an ServerIdentityToml structure back to an ServerIdentity
func (si *ServerIdentityToml) ServerIdentity(suite abstract.Suite) *ServerIdentity {
	pub, err := crypto.Read64Pub(suite, strings.NewReader(si.Public))
	if err != nil {
		log.Error("Error while reading public key:", err)
	}
	return &ServerIdentity{
		Public:  pub,
		Address: si.Address,
	}
}

// GlobalBind returns the global-binding address. Given any IP:PORT combination,
// it will return 0.0.0.0:PORT.
func GlobalBind(address string) (string, error) {
	addr := strings.Split(address, ":")
	if len(addr) != 2 {
		return "", errors.New("Not a host:port address")
	}
	return "0.0.0.0:" + addr[1], nil
}

// counterSafe is a struct that enables to update two counters Rx & Tx
// atomically that can be have increasing values.
// It's main use is for Conn to update how many bytes they've
// written / read. This struct implements the monitor.CounterIO interface.
type counterSafe struct {
	tx uint64
	rx uint64
	sync.Mutex
}

// Rx returns the rx counter
func (c *counterSafe) Rx() uint64 {
	c.Lock()
	defer c.Unlock()
	return c.rx
}

// Tx returns the tx counter
func (c *counterSafe) Tx() uint64 {
	c.Lock()
	defer c.Unlock()
	return c.tx
}

// updateRx adds delta to the rx counter
func (c *counterSafe) updateRx(delta uint64) {
	c.Lock()
	defer c.Unlock()
	c.rx += delta
}

// updateTx adds delta to the tx counter
func (c *counterSafe) updateTx(delta uint64) {
	c.Lock()
	defer c.Unlock()
	c.tx += delta
}
