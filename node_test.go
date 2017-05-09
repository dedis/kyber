package onet

import (
	"testing"

	"github.com/dedis/onet/log"
	"github.com/dedis/onet/network"
	"github.com/satori/go.uuid"
)

const (
	ProtocolChannelsName = "ProtocolChannels"
	ProtocolHandlersName = "ProtocolHandlers"
	ProtocolBlockingName = "ProtocolBlocking"
)

func init() {
	GlobalProtocolRegister(ProtocolHandlersName, NewProtocolHandlers)
	GlobalProtocolRegister("ProtocolBlocking", NewProtocolBlocking)
	GlobalProtocolRegister(ProtocolChannelsName, NewProtocolChannels)
	GlobalProtocolRegister(testProto, NewProtocolTest)
	Incoming = make(chan struct {
		*TreeNode
		NodeTestMsg
	})
}

func TestNodeChannelCreateSlice(t *testing.T) {
	local := NewLocalTest()
	_, _, tree := local.GenTree(2, true)
	defer local.CloseAll()

	p, err := local.CreateProtocol(ProtocolChannelsName, tree)
	if err != nil {
		t.Fatal("Couldn't create new node:", err)
	}

	var c chan []struct {
		*TreeNode
		NodeTestMsg
	}
	tni := p.(*ProtocolChannels).TreeNodeInstance
	err = tni.RegisterChannel(&c)
	if err != nil {
		t.Fatal("Couldn't register channel:", err)
	}
}

func TestNodeChannelCreate(t *testing.T) {
	local := NewLocalTest()
	_, _, tree := local.GenTree(2, true)
	defer local.CloseAll()

	p, err := local.CreateProtocol(ProtocolChannelsName, tree)
	if err != nil {
		t.Fatal("Couldn't create new node:", err)
	}
	var c chan struct {
		*TreeNode
		NodeTestMsg
	}
	tni := p.(*ProtocolChannels).TreeNodeInstance
	err = tni.RegisterChannel(&c)
	if err != nil {
		t.Fatal("Couldn't register channel:", err)
	}
	err = tni.DispatchChannel([]*ProtocolMsg{{
		Msg:     NodeTestMsg{3},
		MsgType: network.RegisterMessage(NodeTestMsg{}),
		From: &Token{
			TreeID:     tree.ID,
			TreeNodeID: tree.Root.ID,
		}},
	})
	if err != nil {
		t.Fatal("Couldn't dispatch to channel:", err)
	}
	msg := <-c
	if msg.I != 3 {
		t.Fatal("Message should contain '3'")
	}
}

func TestNodeChannel(t *testing.T) {
	local := NewLocalTest()
	_, _, tree := local.GenTree(2, true)
	defer local.CloseAll()

	p, err := local.CreateProtocol(ProtocolChannelsName, tree)
	if err != nil {
		t.Fatal("Couldn't create new node:", err)
	}
	c := make(chan struct {
		*TreeNode
		NodeTestMsg
	}, 1)
	tni := p.(*ProtocolChannels).TreeNodeInstance
	err = tni.RegisterChannel(c)
	if err != nil {
		t.Fatal("Couldn't register channel:", err)
	}
	err = tni.DispatchChannel([]*ProtocolMsg{{
		Msg:     NodeTestMsg{3},
		MsgType: network.RegisterMessage(NodeTestMsg{}),
		From: &Token{
			TreeID:     tree.ID,
			TreeNodeID: tree.Root.ID,
		}},
	})
	if err != nil {
		t.Fatal("Couldn't dispatch to channel:", err)
	}
	msg := <-c
	if msg.I != 3 {
		t.Fatal("Message should contain '3'")
	}
}

// Test instantiation of Node
func TestNodeNew(t *testing.T) {
	local := NewLocalTest()
	defer local.CloseAll()

	hosts, _, tree := local.GenTree(2, true)
	h1 := hosts[0]
	// Try directly StartNewNode
	proto, err := h1.StartProtocol(testProto, tree)
	if err != nil {
		t.Fatal("Could not start new protocol", err)
	}
	p := proto.(*ProtocolTest)
	m := <-p.DispMsg
	if m != "Dispatch" {
		t.Fatal("Dispatch() not called - msg is:", m)
	}
	m = <-p.StartMsg
	if m != "Start" {
		t.Fatal("Start() not called - msg is:", m)
	}
}

func TestTreeNodeProtocolHandlers(t *testing.T) {
	local := NewLocalTest()
	_, _, tree := local.GenTree(3, true)
	defer local.CloseAll()
	log.Lvl2("Sending to children")
	IncomingHandlers = make(chan *TreeNodeInstance, 2)
	p, err := local.CreateProtocol(ProtocolHandlersName, tree)
	if err != nil {
		t.Fatal(err)
	}
	go p.Start()
	log.Lvl2("Waiting for response from child 1/2")
	child1 := <-IncomingHandlers
	log.Lvl2("Waiting for response from child 2/2")
	child2 := <-IncomingHandlers

	if child1.ServerIdentity().ID.Equal(child2.ServerIdentity().ID) {
		t.Fatal("Both entities should be different")
	}

	log.Lvl2("Sending to parent")

	tni := p.(*ProtocolHandlers).TreeNodeInstance
	child1.SendTo(tni.TreeNode(), &NodeTestAggMsg{})
	if len(IncomingHandlers) > 0 {
		t.Fatal("This should not trigger yet")
	}
	child2.SendTo(tni.TreeNode(), &NodeTestAggMsg{})
	final := <-IncomingHandlers
	if !final.ServerIdentity().ID.Equal(tni.ServerIdentity().ID) {
		t.Fatal("This should be the same ID")
	}
}

func TestTreeNodeMsgAggregation(t *testing.T) {
	local := NewLocalTest()
	_, _, tree := local.GenTree(3, true)
	defer local.CloseAll()
	root, err := local.StartProtocol(ProtocolChannelsName, tree)
	if err != nil {
		t.Fatal("Couldn't create new node:", err)
	}
	proto := root.(*ProtocolChannels)
	// Wait for both children to be up
	<-Incoming
	<-Incoming
	log.Lvl3("Both children are up")
	child1 := local.getNodes(tree.Root.Children[0])[0]
	child2 := local.getNodes(tree.Root.Children[1])[0]

	err = local.sendTreeNode(ProtocolChannelsName, child1, proto.TreeNodeInstance, &NodeTestAggMsg{3})
	if err != nil {
		t.Fatal(err)
	}
	if len(proto.IncomingAgg) > 0 {
		t.Fatal("Messages should NOT be there")
	}
	err = local.sendTreeNode(ProtocolChannelsName, child2, proto.TreeNodeInstance, &NodeTestAggMsg{4})
	if err != nil {
		t.Fatal(err)
	}

	msgs := <-proto.IncomingAgg
	if msgs[0].I != 3 {
		t.Fatal("First message should be 3")
	}
	if msgs[1].I != 4 {
		t.Fatal("Second message should be 4")
	}

}

func TestTreeNodeFlags(t *testing.T) {
	testType := network.MessageTypeID(uuid.Nil)
	local := NewLocalTest()
	_, _, tree := local.GenTree(3, true)
	defer local.CloseAll()
	p, err := local.CreateProtocol(ProtocolChannelsName, tree)
	if err != nil {
		t.Fatal("Couldn't create node.")
	}
	tni := p.(*ProtocolChannels).TreeNodeInstance
	if tni.hasFlag(testType, AggregateMessages) {
		t.Fatal("Should NOT have AggregateMessages-flag")
	}
	tni.setFlag(testType, AggregateMessages)
	if !tni.hasFlag(testType, AggregateMessages) {
		t.Fatal("Should HAVE AggregateMessages-flag cleared")
	}
	tni.clearFlag(testType, AggregateMessages)
	if tni.hasFlag(testType, AggregateMessages) {
		t.Fatal("Should NOT have AggregateMessages-flag")
	}
}

// Protocol/service Channels test code:
type NodeTestMsg struct {
	I int
}

var Incoming chan struct {
	*TreeNode
	NodeTestMsg
}

type NodeTestAggMsg struct {
	I int
}

type ProtocolChannels struct {
	*TreeNodeInstance
	IncomingAgg chan []struct {
		*TreeNode
		NodeTestAggMsg
	}
}

func NewProtocolChannels(n *TreeNodeInstance) (ProtocolInstance, error) {
	p := &ProtocolChannels{
		TreeNodeInstance: n,
	}
	p.RegisterChannel(Incoming)
	p.RegisterChannel(&p.IncomingAgg)
	return p, nil
}

func (p *ProtocolChannels) Start() error {
	for _, c := range p.Children() {
		err := p.SendTo(c, &NodeTestMsg{12})
		if err != nil {
			return err
		}
	}
	return nil
}

// release resources ==> call Done()
func (p *ProtocolChannels) Release() {
	p.Done()
}

type ServiceChannels struct {
	ctx  *Context
	path string
	tree Tree
}

// implement services interface
func (c *ServiceChannels) ProcessClientRequest(si *network.ServerIdentity, r interface{}) {

	tni := c.ctx.NewTreeNodeInstance(&c.tree, c.tree.Root, ProtocolChannelsName)
	pi, err := NewProtocolChannels(tni)
	if err != nil {
		return
	}

	if err := c.ctx.RegisterProtocolInstance(pi); err != nil {
		return
	}
	pi.Start()
}

func (c *ServiceChannels) NewProtocol(tn *TreeNodeInstance, conf *GenericConfig) (ProtocolInstance, error) {
	log.Lvl1("Cosi Service received New Protocol event")
	return NewProtocolChannels(tn)
}

func (c *ServiceChannels) Process(e *network.Envelope) {
	return
}

// End: protocol/service channels

type ProtocolHandlers struct {
	*TreeNodeInstance
}

var IncomingHandlers chan *TreeNodeInstance

func NewProtocolHandlers(n *TreeNodeInstance) (ProtocolInstance, error) {
	p := &ProtocolHandlers{
		TreeNodeInstance: n,
	}
	if err := p.RegisterHandlers(p.HandleMessageOne,
		p.HandleMessageAggregate); err != nil {
		return nil, err
	}
	return p, nil
}

func (p *ProtocolHandlers) Start() error {
	for _, c := range p.Children() {
		err := p.SendTo(c, &NodeTestMsg{12})
		if err != nil {
			log.Error("Error sending to ", c.Name(), ":", err)
		}
	}
	return nil
}

func (p *ProtocolHandlers) HandleMessageOne(msg struct {
	*TreeNode
	NodeTestMsg
}) error {
	IncomingHandlers <- p.TreeNodeInstance
	return nil
}

func (p *ProtocolHandlers) HandleMessageAggregate(msg []struct {
	*TreeNode
	NodeTestAggMsg
}) error {
	log.Lvl3("Received message")
	IncomingHandlers <- p.TreeNodeInstance
	return nil
}

func (p *ProtocolHandlers) Dispatch() error {
	return nil
}

// release resources ==> call Done()
func (p *ProtocolHandlers) Release() {
	p.Done()
}

func TestNodeBlocking(t *testing.T) {
	l := NewLocalTest()
	_, _, tree := l.GenTree(2, true)
	defer l.CloseAll()

	n1, err := l.StartProtocol("ProtocolBlocking", tree)
	if err != nil {
		t.Fatal("Couldn't start protocol")
	}
	n2, err := l.StartProtocol("ProtocolBlocking", tree)
	if err != nil {
		t.Fatal("Couldn't start protocol")
	}

	p1 := n1.(*BlockingProtocol)
	p2 := n2.(*BlockingProtocol)
	tn1 := p1.TreeNodeInstance
	tn2 := p2.TreeNodeInstance
	go func() {
		// Send two messages to n1, which blocks the old interface
		err := l.sendTreeNode("", tn2, tn1, &NodeTestMsg{})
		if err != nil {
			t.Fatal("Couldn't send message:", err)
		}
		err = l.sendTreeNode("", tn2, tn1, &NodeTestMsg{})
		if err != nil {
			t.Fatal("Couldn't send message:", err)
		}
		// Now send a message to n2, but in the old interface this
		// blocks.
		err = l.sendTreeNode("", tn1, tn2, &NodeTestMsg{})
		if err != nil {
			t.Fatal("Couldn't send message:", err)
		}
	}()
	// Release p2
	p2.stopBlockChan <- true
	<-p2.doneChan
	log.Lvl2("Node 2 done")
	p1.stopBlockChan <- true
	<-p1.doneChan

}

// BlockingProtocol is a protocol that will block until it receives a "continue"
// signal on the continue channel. It is used for testing the asynchronous
// & non blocking handling of the messages in
type BlockingProtocol struct {
	*TreeNodeInstance
	// the protocol will signal on this channel that it is done
	doneChan chan bool
	// stopBLockChan is used to signal the protocol to stop blocking the
	// incoming messages on the Incoming chan
	stopBlockChan chan bool
	Incoming      chan struct {
		*TreeNode
		NodeTestMsg
	}
}

func NewProtocolBlocking(node *TreeNodeInstance) (ProtocolInstance, error) {
	bp := &BlockingProtocol{
		TreeNodeInstance: node,
		doneChan:         make(chan bool),
		stopBlockChan:    make(chan bool),
	}

	log.ErrFatal(node.RegisterChannel(&bp.Incoming))
	return bp, nil
}

func (bp *BlockingProtocol) Start() error {
	return nil
}

func (bp *BlockingProtocol) Dispatch() error {
	// first wait on stopBlockChan
	<-bp.stopBlockChan
	log.Lvl2("BlockingProtocol: will continue")
	// Then wait on the actual message
	<-bp.Incoming
	log.Lvl2("BlockingProtocol: received message => signal Done")
	// then signal that you are done
	bp.doneChan <- true
	return nil
}
