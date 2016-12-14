package manage

import (
	"sync"

	"time"

	"reflect"

	"github.com/dedis/onet"
	"github.com/dedis/onet/log"
	"github.com/dedis/onet/network"
)

func init() {
	network.RegisterPacketType(PropagateSendData{})
	network.RegisterPacketType(PropagateReply{})
}

// Propagate is a protocol that sends some data to all attached nodes
// and waits for confirmation before returning.
type Propagate struct {
	*onet.TreeNodeInstance
	onData    PropagationStore
	onDoneCb  func(int)
	sd        *PropagateSendData
	ChannelSD chan struct {
		*onet.TreeNode
		PropagateSendData
	}
	ChannelReply chan struct {
		*onet.TreeNode
		PropagateReply
	}

	received     int
	subtreeCount int
	sync.Mutex
}

// PropagateSendData is the message to pass the data to the children
type PropagateSendData struct {
	// Data is the data to transmit
	Data []byte
	// How long the root will wait for the children before
	// timing out
	Msec int
}

// PropagateReply is sent from the children back to the root
type PropagateReply struct {
	Level int
}

// PropagationFunc starts the propagation protocol and blocks until
// all children stored the new value or the timeout has been reached.
// The return value is the number of nodes that acknowledged having
// stored the new value or an error if the protocol couldn't start.
type PropagationFunc func(el *onet.Roster, msg network.Body, msec int) (int, error)

// PropagationStore is the function that will store the new data.
type PropagationStore func(network.Body)

// propagationContext is used for testing.
type propagationContext interface {
	ProtocolRegister(name string, protocol onet.NewProtocol) (onet.ProtocolID, error)
	ServerIdentity() *network.ServerIdentity
	CreateProtocolSDA(name string, t *onet.Tree) (onet.ProtocolInstance, error)
}

// NewPropagationFunc registers a new protocol name with the context c and will
// set f as handler for every new instance of that protocol.
func NewPropagationFunc(c propagationContext, name string, f PropagationStore) (PropagationFunc, error) {
	pid, err := c.ProtocolRegister(name, func(n *onet.TreeNodeInstance) (onet.ProtocolInstance, error) {
		p := &Propagate{
			sd:               &PropagateSendData{[]byte{}, 1000},
			TreeNodeInstance: n,
			received:         0,
			subtreeCount:     n.TreeNode().SubtreeCount(),
			onData:           f,
		}
		for _, h := range []interface{}{&p.ChannelSD, &p.ChannelReply} {
			if err := p.RegisterChannel(h); err != nil {
				return nil, err
			}
		}
		return p, nil
	})
	log.Lvl3("Registering new propagation for", c.ServerIdentity(),
		name, pid)
	return func(el *onet.Roster, msg network.Body, msec int) (int, error) {
		tree := el.GenerateNaryTreeWithRoot(8, c.ServerIdentity())
		log.Lvl3(el.List[0].Address, "Starting to propagate", reflect.TypeOf(msg))
		pi, err := c.CreateProtocolSDA(name, tree)
		if err != nil {
			return -1, err
		}
		return propagateStartAndWait(pi, msg, msec, f)
	}, err
}

// Separate function for testing
func propagateStartAndWait(pi onet.ProtocolInstance, msg network.Body, msec int, f PropagationStore) (int, error) {
	d, err := network.MarshalRegisteredType(msg)
	if err != nil {
		return -1, err
	}
	protocol := pi.(*Propagate)
	protocol.Lock()
	protocol.sd.Data = d
	protocol.sd.Msec = msec
	protocol.onData = f

	done := make(chan int)
	protocol.onDoneCb = func(i int) { done <- i }
	protocol.Unlock()
	if err = protocol.Start(); err != nil {
		return -1, err
	}
	ret := <-done
	log.Lvl3("Finished propagation with", ret, "replies")
	return ret, nil
}

// Start will contact everyone and make the connections
func (p *Propagate) Start() error {
	log.Lvl4("going to contact", p.Root().ServerIdentity)
	p.SendTo(p.Root(), p.sd)
	return nil
}

// Dispatch can handle timeouts
func (p *Propagate) Dispatch() error {
	process := true
	log.Lvl4(p.ServerIdentity())
	for process {
		p.Lock()
		timeout := time.Millisecond * time.Duration(p.sd.Msec)
		p.Unlock()
		select {
		case msg := <-p.ChannelSD:
			log.Lvl3(p.ServerIdentity(), "Got data from", msg.ServerIdentity, "and setting timeout to", msg.Msec)
			p.sd.Msec = msg.Msec
			if p.onData != nil {
				_, netMsg, err := network.UnmarshalRegistered(msg.Data)
				if err == nil {
					p.onData(netMsg)
				}
			}
			if !p.IsRoot() {
				log.Lvl3(p.ServerIdentity(), "Sending to parent")
				p.SendToParent(&PropagateReply{})
			}
			if p.IsLeaf() {
				process = false
			} else {
				log.Lvl3(p.ServerIdentity(), "Sending to children")
				p.SendToChildren(&msg.PropagateSendData)
			}
		case <-p.ChannelReply:
			p.received++
			log.Lvl4(p.ServerIdentity(), "received:", p.received, p.subtreeCount)
			if !p.IsRoot() {
				p.SendToParent(&PropagateReply{})
			}
			if p.received == p.subtreeCount {
				process = false
			}
		case <-time.After(timeout):
			_, a, err := network.UnmarshalRegistered(p.sd.Data)
			log.Fatalf("Timeout of %s reached. %v %s", timeout, a, err)
			process = false
		}
	}
	if p.IsRoot() {
		if p.onDoneCb != nil {
			p.onDoneCb(p.received + 1)
		}
	}
	p.Done()
	return nil
}

// RegisterOnDone takes a function that will be called once the data has been
// sent to the whole tree. It receives the number of nodes that replied
// successfully to the propagation.
func (p *Propagate) RegisterOnDone(fn func(int)) {
	p.onDoneCb = fn
}

// RegisterOnData takes a function that will be called for that node if it
// needs to update its data.
func (p *Propagate) RegisterOnData(fn PropagationStore) {
	p.onData = fn
}

// Config stores the basic configuration for that protocol.
func (p *Propagate) Config(d []byte, msec int) {
	p.sd.Data = d
	p.sd.Msec = msec
}
