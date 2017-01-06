package onet

import "github.com/dedis/onet/network"

// Context represents the methods that are available to a service.
type Context struct {
	overlay *Overlay
	conode  *Conode
	servID  ServiceID
	manager *serviceManager
	network.Dispatcher
}

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
func (c *Context) ReportStatus() map[string]Status {
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
