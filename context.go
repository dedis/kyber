package onet

import (
	"errors"
	"fmt"

	"io/ioutil"

	"os/user"
	"path"

	"runtime"

	"os"

	"flag"

	"github.com/dedis/onet/log"
	"github.com/dedis/onet/network"
)

// Context represents the methods that are available to a service.
type Context struct {
	overlay *Overlay
	conode  *Conode
	servID  ServiceID
	manager *serviceManager
	network.Dispatcher
}

// ENVServiceData is the environmental variable that can be used to override the
// service-data-path.
const ENVServiceData = "CONODE_SERVICE_PATH"

// defaultContext is the implementation of the Context interface. It is
// instantiated for each Service.
func newContext(c *Conode, o *Overlay, servID ServiceID, manager *serviceManager) *Context {
	return &Context{
		overlay:    o,
		conode:     c,
		servID:     servID,
		manager:    manager,
		Dispatcher: network.NewBlockingDispatcher(),
	}
}

// contextDataPath indicates where the service-data will be stored. If it is
// empty, a memory-map is used.
var contextDataPath = ""

func init() {
	if flag.Lookup("test.v") == nil {
		initContextDataPath()
	}
}

// NewTreeNodeInstance creates a TreeNodeInstance that is bound to a
// service instead of the Overlay.
func (c *Context) NewTreeNodeInstance(t *Tree, tn *TreeNode, protoName string) *TreeNodeInstance {
	io := c.overlay.protoIO.getByName(protoName)
	return c.overlay.NewTreeNodeInstanceFromService(t, tn, ProtocolNameToID(protoName), c.servID, io)
}

// SendRaw sends a message to the ServerIdentity.
func (c *Context) SendRaw(si *network.ServerIdentity, msg interface{}) error {
	return c.conode.Send(si, msg)
}

// ServerIdentity returns this Conode's identity.
func (c *Context) ServerIdentity() *network.ServerIdentity {
	return c.conode.ServerIdentity
}

// ServiceID returns the service-id.
func (c *Context) ServiceID() ServiceID {
	return c.servID
}

// CreateProtocol returns a ProtocolInstance bound to the service.
func (c *Context) CreateProtocol(name string, t *Tree) (ProtocolInstance, error) {
	pi, err := c.overlay.CreateProtocol(name, t, c.servID)
	return pi, err
}

// ProtocolRegister signs up a new protocol to this Conode. Contrary go
// GlobalProtocolRegister, the protocol registered here is tied to that conode.
// This is useful for simulations where more than one Conode exists in the
// global namespace.
// It returns the ID of the protocol.
func (c *Context) ProtocolRegister(name string, protocol NewProtocol) (ProtocolID, error) {
	return c.conode.ProtocolRegister(name, protocol)
}

// RegisterProtocolInstance registers a new instance of a protocol using overlay.
func (c *Context) RegisterProtocolInstance(pi ProtocolInstance) error {
	return c.overlay.RegisterProtocolInstance(pi)
}

// ReportStatus returns all status of the services.
func (c *Context) ReportStatus() map[string]*Status {
	return c.conode.statusReporterStruct.ReportStatus()
}

// RegisterStatusReporter registers a new StatusReporter.
func (c *Context) RegisterStatusReporter(name string, s StatusReporter) {
	c.conode.statusReporterStruct.RegisterStatusReporter(name, s)
}

// RegisterProcessor overrides the RegisterProcessor methods of the Dispatcher.
// It delegates the dispatching to the serviceManager.
func (c *Context) RegisterProcessor(p network.Processor, msgType network.PacketTypeID) {
	c.manager.RegisterProcessor(p, msgType)
}

// RegisterProcessorFunc takes a message-type and a function that will be called
// if this message-type is received.
func (c *Context) RegisterProcessorFunc(msgType network.PacketTypeID, fn func(*network.Packet)) {
	c.manager.RegisterProcessorFunc(msgType, fn)
}

// Service returns the corresponding service.
func (c *Context) Service(name string) Service {
	return c.manager.Service(name)
}

// String returns the host it's running on.
func (c *Context) String() string {
	return c.conode.ServerIdentity.String()
}

var contextData = map[string][]byte{}

// Save takes an identifier and an interface. The interface will be network.Marshaled
// and written to the filename based on the identifier. An eventual error will be returned.
// If the destination is a file, it will be created with rw-r----- permissions
// (0640).
func (c *Context) Save(id string, data interface{}) error {
	buf, err := network.MarshalRegisteredType(data)
	if err != nil {
		return err
	}
	fname := c.Path(id)
	if contextDataPath == "" {
		contextData[fname] = buf
		return nil
	}
	return ioutil.WriteFile(fname, buf, 0640)
}

// Load takes a filename and returns the network.Unmarshaled data. If an error
// occurs, the data is nil.
// The file is read from a service-conode owned directory, so two services have
// two distinct directories.
func (c *Context) Load(id string) (interface{}, error) {
	var buf []byte
	if contextDataPath == "" {
		var ok bool
		buf, ok = contextData[c.Path(id)]
		if !ok {
			return nil, errors.New("This entry doesn't exist")
		}
	} else {
		var err error
		buf, err = ioutil.ReadFile(c.Path(id))
		if err != nil {
			return nil, err
		}
	}
	_, ret, err := network.UnmarshalRegistered(buf)
	return ret, err
}

// Path returns the absolute path to load and save the configuration.
// The file is chosen as "#{ServerIdentity.Public}_#{ServiceName}_#{id}.bin",
// so no service and no conode share the same file.
func (c *Context) Path(id string) string {
	pub, _ := c.ServerIdentity().Public.MarshalBinary()
	return path.Join(contextDataPath, fmt.Sprintf("%x_%s_%s.bin", pub,
		ServiceFactory.Name(c.ServiceID()), id))
}

// Returns the path to the file for storage/retrieval of the service-state.
// It choses a suitable name for MacOS/Linux/Windows and also
// accepts an override with the environmental-variable "CONODE_SERVICE_DATA".
// Mac: ~/Library/Conode/Services
// Other Unix: ~/.local/share/conode
// Windows: $HOME$\AppData\Local\Conode
// If the directory doesn't exist, it will be created using rwxr-x---
// permissions (0750).
func initContextDataPath() {
	// Set contextDataMemory to true if we're running in a test
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
	os.MkdirAll(p, 0750)
	contextDataPath = p
}
