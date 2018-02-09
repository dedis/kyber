package onet

import (
	"errors"
	"fmt"
	"os"
	"path"
	"strconv"

	"sync"

	bolt "github.com/coreos/bbolt"
	"github.com/dedis/onet/log"
	"github.com/dedis/onet/network"
	"gopkg.in/satori/go.uuid.v1"
)

func init() {
	network.RegisterMessage(GenericConfig{})
}

// Service is a generic interface to define any type of services.
// A Service has multiple roles:
// * Processing websocket client requests with ProcessClientRequests
// * Handling onet information to ProtocolInstances created with
//  	NewProtocol
// * Handling any kind of messages between Services between different hosts with
//   	the Processor interface
type Service interface {
	// NewProtocol is called upon a ProtocolInstance's first message when Onet needs
	// to instantiate the protocol. A Service is expected to manually create
	// the ProtocolInstance it is using. If a Service returns (nil,nil), that
	// means this Service lets Onet handle the protocol instance.
	NewProtocol(*TreeNodeInstance, *GenericConfig) (ProtocolInstance, error)
	// ProcessClientRequest is called when a message from an
	// external client is received by the websocket for this
	// service. It returns a message that will be sent back to the
	// client. The returned error will be formatted as a websocket
	// error code 4000, using the string form of the error as the message.
	ProcessClientRequest(handler string, msg []byte) (reply []byte, err error)
	// Processor makes a Service being able to handle any kind of packets
	// directly from the network. It is used for inter service communications,
	// which are mostly single packets with no or little interactions needed. If
	// a complex logic is used for these messages, it's best to put that logic
	// into a ProtocolInstance that the Service will launch, since there's nicer
	// utilities for ProtocolInstance.
	network.Processor
}

// NewServiceFunc is the type of a function that is used to instantiate a given Service
// A service is initialized with a Server (to send messages to someone).
type NewServiceFunc func(c *Context) (Service, error)

// ServiceID is a type to represent a uuid for a Service
type ServiceID uuid.UUID

// String returns the string representation of this ServiceID
func (s ServiceID) String() string {
	return uuid.UUID(s).String()
}

// Equal returns true if and only if s2 equals this ServiceID.
func (s ServiceID) Equal(s2 ServiceID) bool {
	return uuid.Equal(uuid.UUID(s), uuid.UUID(s2))
}

// IsNil returns true iff the ServiceID is Nil
func (s ServiceID) IsNil() bool {
	return s.Equal(ServiceID(uuid.Nil))
}

// NilServiceID is the empty ServiceID
var NilServiceID = ServiceID(uuid.Nil)

// GenericConfig is a config that can withhold any type of specific configs for
// protocols. It is passed down to the service NewProtocol function.
type GenericConfig struct {
	Data []byte
}

// A serviceFactory is used to register a NewServiceFunc
type serviceFactory struct {
	constructors []serviceEntry
	mutex        sync.RWMutex
}

// A serviceEntry holds all references to a service
type serviceEntry struct {
	constructor NewServiceFunc
	serviceID   ServiceID
	name        string
}

// ServiceFactory is the global service factory to instantiate Services
var ServiceFactory = serviceFactory{
	constructors: []serviceEntry{},
}

// Register takes a name and a function, then creates a ServiceID out of it and stores the
// mapping and the creation function.
func (s *serviceFactory) Register(name string, fn NewServiceFunc) (ServiceID, error) {
	if !s.ServiceID(name).Equal(NilServiceID) {
		return NilServiceID, fmt.Errorf("service %s already registered", name)
	}
	id := ServiceID(uuid.NewV5(uuid.NamespaceURL, name))
	s.mutex.Lock()
	defer s.mutex.Unlock()
	s.constructors = append(s.constructors, serviceEntry{
		constructor: fn,
		serviceID:   id,
		name:        name,
	})
	return id, nil
}

// Unregister - mainly for tests
func (s *serviceFactory) Unregister(name string) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	index := -1
	for i, c := range s.constructors {
		if c.name == name {
			index = i
			break
		}
	}
	if index < 0 {
		return errors.New("Didn't find service " + name)
	}
	s.constructors = append(s.constructors[:index], s.constructors[index+1:]...)
	return nil
}

// RegisterNewService is a wrapper around service factory
func RegisterNewService(name string, fn NewServiceFunc) (ServiceID, error) {
	return ServiceFactory.Register(name, fn)
}

// UnregisterService removes a service from the global pool.
func UnregisterService(name string) error {
	return ServiceFactory.Unregister(name)
}

// registeredServiceIDs returns all the services registered
func (s *serviceFactory) registeredServiceIDs() []ServiceID {
	s.mutex.RLock()
	defer s.mutex.RUnlock()
	var ids = make([]ServiceID, 0, len(s.constructors))
	for _, c := range s.constructors {
		ids = append(ids, c.serviceID)
	}
	return ids
}

// RegisteredServiceNames returns all the names of the services registered
func (s *serviceFactory) RegisteredServiceNames() []string {
	s.mutex.RLock()
	defer s.mutex.RUnlock()
	var names = make([]string, 0, len(s.constructors))
	for _, n := range s.constructors {
		names = append(names, n.name)
	}
	return names
}

// ServiceID returns the ServiceID out of the name of the service
func (s *serviceFactory) ServiceID(name string) ServiceID {
	s.mutex.RLock()
	defer s.mutex.RUnlock()
	for _, c := range s.constructors {
		if name == c.name {
			return c.serviceID
		}
	}
	return NilServiceID
}

// Name returns the Name out of the ID
func (s *serviceFactory) Name(id ServiceID) string {
	s.mutex.RLock()
	defer s.mutex.RUnlock()
	for _, c := range s.constructors {
		if id.Equal(c.serviceID) {
			return c.name
		}
	}
	return ""
}

// start launches a new service
func (s *serviceFactory) start(name string, con *Context) (Service, error) {
	s.mutex.RLock()
	defer s.mutex.RUnlock()
	for _, c := range s.constructors {
		if name == c.name {
			return c.constructor(con)
		}
	}
	return nil, errors.New("Didn't find service " + name)
}

// serviceManager is the place where all instantiated services are stored
// It gives access to: all the currently running services
type serviceManager struct {
	// the actual services
	services map[ServiceID]Service
	// the onet host
	server *Server
	// a bbolt database for all services
	db     *bolt.DB
	dbPath string
	// should the db be deleted on close?
	delDb bool
	// the dispatcher can take registration of Processors
	network.Dispatcher
}

// newServiceManager will create a serviceStore out of all the registered Service
func newServiceManager(svr *Server, o *Overlay, dbPath string, delDb bool) *serviceManager {
	services := make(map[ServiceID]Service)
	s := &serviceManager{
		services:   services,
		server:     svr,
		dbPath:     dbPath,
		delDb:      delDb,
		Dispatcher: network.NewRoutineDispatcher(),
	}

	db, err := openDb(s.dbFileName())
	if err != nil {
		log.Panic("Failed to create new database: " + err.Error())
	}
	s.db = db

	ids := ServiceFactory.registeredServiceIDs()
	for _, id := range ids {
		name := ServiceFactory.Name(id)
		log.Lvl3("Starting service", name)

		err = createBucketForService(s.db, name)
		if err != nil {
			log.Panic("Failed to create bucket: " + err.Error())
		}

		cont := newContext(svr, o, id, s)
		s, err := ServiceFactory.start(name, cont)
		if err != nil {
			log.Panic("Trying to instantiate service", name, ":", err)
		}
		log.Lvl3("Started Service", name)
		services[id] = s
		svr.websocket.registerService(name, s)
	}
	log.Lvl3(svr.Address(), "instantiated all services")
	svr.statusReporterStruct.RegisterStatusReporter("Db", s)
	return s
}

// openDb opens a database at `path`. It creates the database if it does not exist.
// The caller must ensure that all parent directories exist.
func openDb(path string) (*bolt.DB, error) {
	db, err := bolt.Open(path, 0600, nil)
	if err != nil {
		return nil, err
	}
	return db, nil
}

// createBucketForService creates a bucket in the database `db` named `bucketName`.
func createBucketForService(db *bolt.DB, bucketName string) error {
	return db.Update(func(tx *bolt.Tx) error {
		_, err := tx.CreateBucketIfNotExists([]byte(bucketName))
		return err
	})
}

func (s *serviceManager) dbFileName() string {
	pub, _ := s.server.ServerIdentity.Public.MarshalBinary()
	return path.Join(s.dbPath, fmt.Sprintf("%x.db", pub))
}

// Process implements the Processor interface: service manager will relay
// messages to the right Service.
func (s *serviceManager) Process(env *network.Envelope) {
	// will launch a go routine for that message
	s.Dispatch(env)
}

// closeDatabase closes the database.
// It also removes the database file if the path is not default (i.e. testing config)
func (s *serviceManager) closeDatabase() error {
	if s.db != nil {
		err := s.db.Close()
		if err != nil {
			log.Error("Close database failed with: " + err.Error())
		}
	}

	if s.delDb {
		err := os.Remove(s.dbFileName())
		if err != nil {
			return err
		}
	}
	return nil
}

// GetStatus is a function that returns the status report of the server.
func (s *serviceManager) GetStatus() Status {
	if s.db == nil {
		return Status(map[string]string{"Open": "false"})
	}
	st := s.db.Stats()
	return Status(map[string]string{
		"Open":             "true",
		"FreePageN":        strconv.Itoa(st.FreePageN),
		"PendingPageN":     strconv.Itoa(st.PendingPageN),
		"FreeAlloc":        strconv.Itoa(st.FreeAlloc),
		"FreelistInuse":    strconv.Itoa(st.FreelistInuse),
		"TxN":              strconv.Itoa(st.TxN),
		"OpenTxN":          strconv.Itoa(st.OpenTxN),
		"Tx.PageCount":     strconv.Itoa(st.TxStats.PageCount),
		"Tx.PageAlloc":     strconv.Itoa(st.TxStats.PageAlloc),
		"Tx.CursorCount":   strconv.Itoa(st.TxStats.CursorCount),
		"Tx.NodeCount":     strconv.Itoa(st.TxStats.NodeCount),
		"Tx.NodeDeref":     strconv.Itoa(st.TxStats.NodeDeref),
		"Tx.Rebalance":     strconv.Itoa(st.TxStats.Rebalance),
		"Tx.RebalanceTime": st.TxStats.RebalanceTime.String(),
		"Tx.Split":         strconv.Itoa(st.TxStats.Split),
		"Tx.Spill":         strconv.Itoa(st.TxStats.Spill),
		"Tx.SpillTime":     st.TxStats.SpillTime.String(),
		"Tx.Write":         strconv.Itoa(st.TxStats.Write),
		"Tx.WriteTime":     st.TxStats.WriteTime.String(),
	})
}

// registerProcessor the processor to the service manager and tells the host to dispatch
// this message to the service manager. The service manager will then dispatch
// the message in a go routine. XXX This is needed because we need to have
// messages for service dispatched in asynchronously regarding the protocols.
// This behavior with go routine is fine for the moment but for better
// performance / memory / resilience, it may be changed to a real queuing
// system later.
func (s *serviceManager) registerProcessor(p network.Processor, msgType network.MessageTypeID) {
	// delegate message to host so the host will pass the message to ourself
	s.server.RegisterProcessor(s, msgType)
	// handle the message ourselves (will be launched in a go routine)
	s.Dispatcher.RegisterProcessor(p, msgType)
}

func (s *serviceManager) registerProcessorFunc(msgType network.MessageTypeID, fn func(*network.Envelope)) {
	// delegate message to host so the host will pass the message to ourself
	s.server.RegisterProcessor(s, msgType)
	// handle the message ourselves (will be launched in a go routine)
	s.Dispatcher.RegisterProcessorFunc(msgType, fn)

}

// availableServices returns a list of all services available to the serviceManager.
// If no services are instantiated, it returns an empty list.
func (s *serviceManager) availableServices() (ret []string) {
	for id := range s.services {
		ret = append(ret, ServiceFactory.Name(id))
	}
	return
}

// service returns the service implementation being registered to this name or
// nil if no service by this name is available.
func (s *serviceManager) service(name string) Service {
	id := ServiceFactory.ServiceID(name)
	if id.Equal(NilServiceID) {
		return nil
	}
	return s.services[id]
}

func (s *serviceManager) serviceByID(id ServiceID) (Service, bool) {
	var serv Service
	var ok bool
	if serv, ok = s.services[id]; !ok {
		return nil, false
	}
	return serv, true
}

// newProtocol contains the logic of how and where a ProtocolInstance is
// created. If the token's ServiceID is nil, then onet handles the creation of
// the PI. If the corresponding service returns (nil,nil), then onet handles
// the creation of the PI. Otherwise the service is responsible for setting up
// the PI.
func (s *serviceManager) newProtocol(tni *TreeNodeInstance, config *GenericConfig) (ProtocolInstance, error) {
	si, ok := s.serviceByID(tni.Token().ServiceID)
	defaultHandle := func() (ProtocolInstance, error) { return s.server.protocolInstantiate(tni.Token().ProtoID, tni) }
	if !ok {
		// let onet handle it
		return defaultHandle()
	}
	pi, err := si.NewProtocol(tni, config)
	if pi == nil && err == nil {
		return defaultHandle()
	}
	return pi, err
}
