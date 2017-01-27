package onet

import (
	"errors"
	"fmt"

	"io/ioutil"

	"os/user"
	"path"

	"runtime"

	"os"

	"sync"

	"github.com/dedis/onet/log"
	"github.com/dedis/onet/network"
)

// Context represents the methods that are available to a service.
type Context struct {
	overlay   *Overlay
	server    *Server
	serviceID ServiceID
	manager   *serviceManager
	network.Dispatcher
}

// ENVServiceData is the environmental variable that can be used to override the
// service-data-path.
const ENVServiceData = "CONODE_SERVICE_PATH"

// defaultContext is the implementation of the Context interface. It is
// instantiated for each Service.
func newContext(c *Server, o *Overlay, servID ServiceID, manager *serviceManager) *Context {
	return &Context{
		overlay:    o,
		server:     c,
		serviceID:  servID,
		manager:    manager,
		Dispatcher: network.NewBlockingDispatcher(),
	}
}

// contextDataPath indicates where the service-data will be stored. If it is
// empty, a memory-map is used.
var contextDataPath = ""

func init() {
	initContextDataPath()
}

// NewTreeNodeInstance creates a TreeNodeInstance that is bound to a
// service instead of the Overlay.
func (c *Context) NewTreeNodeInstance(t *Tree, tn *TreeNode, protoName string) *TreeNodeInstance {
	io := c.overlay.protoIO.getByName(protoName)
	return c.overlay.NewTreeNodeInstanceFromService(t, tn, ProtocolNameToID(protoName), c.serviceID, io)
}

// SendRaw sends a message to the ServerIdentity.
func (c *Context) SendRaw(si *network.ServerIdentity, msg interface{}) error {
	return c.server.Send(si, msg)
}

// ServerIdentity returns this server's identity.
func (c *Context) ServerIdentity() *network.ServerIdentity {
	return c.server.ServerIdentity
}

// ServiceID returns the service-id.
func (c *Context) ServiceID() ServiceID {
	return c.serviceID
}

// CreateProtocol returns a ProtocolInstance bound to the service.
func (c *Context) CreateProtocol(name string, t *Tree) (ProtocolInstance, error) {
	pi, err := c.overlay.CreateProtocol(name, t, c.serviceID)
	return pi, err
}

// ProtocolRegister signs up a new protocol to this Server. Contrary go
// GlobalProtocolRegister, the protocol registered here is tied to that server.
// This is useful for simulations where more than one Server exists in the
// global namespace.
// It returns the ID of the protocol.
func (c *Context) ProtocolRegister(name string, protocol NewProtocol) (ProtocolID, error) {
	return c.server.ProtocolRegister(name, protocol)
}

// RegisterProtocolInstance registers a new instance of a protocol using overlay.
func (c *Context) RegisterProtocolInstance(pi ProtocolInstance) error {
	return c.overlay.RegisterProtocolInstance(pi)
}

// ReportStatus returns all status of the services.
func (c *Context) ReportStatus() map[string]*Status {
	return c.server.statusReporterStruct.ReportStatus()
}

// RegisterStatusReporter registers a new StatusReporter.
func (c *Context) RegisterStatusReporter(name string, s StatusReporter) {
	c.server.statusReporterStruct.RegisterStatusReporter(name, s)
}

// RegisterProcessor overrides the RegisterProcessor methods of the Dispatcher.
// It delegates the dispatching to the serviceManager.
func (c *Context) RegisterProcessor(p network.Processor, msgType network.MessageTypeID) {
	c.manager.registerProcessor(p, msgType)
}

// RegisterProcessorFunc takes a message-type and a function that will be called
// if this message-type is received.
func (c *Context) RegisterProcessorFunc(msgType network.MessageTypeID, fn func(*network.Envelope)) {
	c.manager.registerProcessorFunc(msgType, fn)
}

// Service returns the corresponding service.
func (c *Context) Service(name string) Service {
	return c.manager.service(name)
}

// String returns the host it's running on.
func (c *Context) String() string {
	return c.server.ServerIdentity.String()
}

var contextData = map[string][]byte{}

// Save takes an identifier and an interface. The interface will be network.Marshaled
// and saved under a filename based on the identifier. An eventual error will be returned.
// If contextDataPath is non-empty, the destination is a file: it will be created
// with rw-r----- permissions (0640). If the file already exists, it will be overwritten.
//
// The path to the file is chosen as follows:
//   Mac: ~/Library/Conode/Services
//   Other Unix: ~/.local/share/conode
//   Windows: $HOME$\AppData\Local\Conode
// If the directory doesn't exist, it will be created using rwxr-x---
// permissions (0750).
// The path can be overwritten with the environmental-variable "CONODE_SERVICE_DATA".
//
// If contextDataPath is empty, the data will be written to the contextData map.
func (c *Context) Save(id string, data interface{}) error {
	buf, err := network.Marshal(data)
	if err != nil {
		return err
	}
	fname := c.absFilename(id)
	if getContextDataPath() == "" {
		contextData[fname] = buf
		return nil
	}
	return ioutil.WriteFile(fname, buf, 0640)
}

// Load takes an id and returns the network.Unmarshaled data. If an error
// occurs, the data is nil.
// If contextDataPath is non-empty, the data will be read from the corresponding
// file. The path is explained in Save().
// If contextDataPath is empty, the data will be read from the contextData map.
//
// If no data is found in either a file or the map, it returns an error.
func (c *Context) Load(id string) (interface{}, error) {
	var buf []byte
	if getContextDataPath() == "" {
		var ok bool
		buf, ok = contextData[c.absFilename(id)]
		if !ok {
			return nil, errors.New("This entry doesn't exist")
		}
	} else {
		var err error
		buf, err = ioutil.ReadFile(c.absFilename(id))
		if err != nil {
			return nil, err
		}
	}
	_, ret, err := network.Unmarshal(buf)
	return ret, err
}

// DataAvailable checks if any data is stored either in a file or in the
// contextData map.
func (c *Context) DataAvailable(id string) bool {
	if getContextDataPath() == "" {
		_, ok := contextData[c.absFilename(id)]
		return ok
	}
	_, err := os.Stat(c.absFilename(id))
	return !os.IsNotExist(err)
}

// absFilename returns the absolute path to load and save the configuration.
// The file is chosen as "#{ServerIdentity.Public}_#{ServiceName}_#{id}.bin",
// so no service and no server share the same file.
func (c *Context) absFilename(id string) string {
	pub, _ := c.ServerIdentity().Public.MarshalBinary()
	return path.Join(getContextDataPath(), fmt.Sprintf("%x_%s_%s.bin", pub,
		ServiceFactory.Name(c.ServiceID()), id))
}

// Returns the path to the file for storage/retrieval of the service-state.
func initContextDataPath() {
	p := os.Getenv(ENVServiceData)
	if p == "" {
		u, err := user.Current()
		if err != nil {
			log.Fatal("Couldn't get current user's environment:", err)
		}
		switch runtime.GOOS {
		case "darwin":
			p = path.Join(u.HomeDir, "Library", "Conode", "Services")
		case "freebsd", "linux", "netbsd", "openbsd", "plan9", "solaris":
			p = path.Join(u.HomeDir, ".local", "share", "conode")
		case "windows":
			p = path.Join(u.HomeDir, "AppData", "Local", "Conode")
		default:
			log.Fatal("Couldn't find OS")
		}
	}
	log.ErrFatal(os.MkdirAll(p, 0750))
	setContextDataPath(p)
}

var cdpMutex sync.Mutex

func setContextDataPath(path string) {
	cdpMutex.Lock()
	defer cdpMutex.Unlock()
	contextDataPath = path
}

func getContextDataPath() string {
	cdpMutex.Lock()
	defer cdpMutex.Unlock()
	return contextDataPath
}
