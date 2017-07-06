package onet

import (
	"errors"
	"fmt"
	"testing"

	"github.com/satori/go.uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/dedis/onet.v2/log"
	"gopkg.in/dedis/onet.v2/network"
)

var testProto = "test"

func init() {
	network.RegisterMessage(SimpleMessage{})
}

// ProtocolTest is the most simple protocol to be implemented, ignoring
// everything it receives.
type ProtocolTest struct {
	*TreeNodeInstance
	StartMsg chan string
	DispMsg  chan string
}

// NewProtocolTest is used to create a new protocolTest-instance
func NewProtocolTest(n *TreeNodeInstance) (ProtocolInstance, error) {
	return &ProtocolTest{
		TreeNodeInstance: n,
		StartMsg:         make(chan string, 1),
		DispMsg:          make(chan string),
	}, nil
}

// Dispatch is used to send the messages further - here everything is
// copied to /dev/null
func (p *ProtocolTest) Dispatch() error {
	log.Lvl2("ProtocolTest.Dispatch()")
	p.DispMsg <- "Dispatch"
	return nil
}

func (p *ProtocolTest) Start() error {
	log.Lvl2("ProtocolTest.Start()")
	p.StartMsg <- "Start"
	return nil
}

type SimpleProtocol struct {
	// chan to get back to testing
	Chan  chan bool
	Error error
	*TreeNodeInstance
}

// Sends a simple message to its first children
func (p *SimpleProtocol) Start() error {
	err := p.SendTo(p.Children()[0], &SimpleMessage{10})
	if err != nil {
		return err
	}
	p.Chan <- true
	return nil
}

// Dispatch analyses the message and does nothing else
func (p *SimpleProtocol) ReceiveMessage(msg MsgSimpleMessage) error {
	if msg.I != 10 {
		return errors.New("Not the value expected")
	}
	p.Chan <- true
	return nil
}

// ReturnError sends a message to the parent, and if it's the parent
// receiving the message, it triggers the channel
func (p *SimpleProtocol) ReturnError(msg MsgSimpleMessage) error {
	if msg.I == 10 {
		p.SendToParent(&SimpleMessage{9})
	} else {
		p.Chan <- true
	}
	return p.Error
}

type SimpleMessage struct {
	I int
}

type MsgSimpleMessage struct {
	*TreeNode
	SimpleMessage
}

// Test simple protocol-implementation
// - registration
func TestProtocolRegistration(t *testing.T) {
	testProtoName := "testProto"
	testProtoID, err := GlobalProtocolRegister(testProtoName, NewProtocolTest)
	log.ErrFatal(err)
	_, err = GlobalProtocolRegister(testProtoName, NewProtocolTest)
	require.NotNil(t, err)
	if !protocols.ProtocolExists(testProtoID) {
		t.Fatal("Test should exist now")
	}
	if !ProtocolNameToID(testProtoName).Equal(testProtoID) {
		t.Fatal("Not correct translation from string to ID")
	}
	require.Equal(t, "", protocols.ProtocolIDToName(ProtocolID(uuid.Nil)))
	if protocols.ProtocolIDToName(testProtoID) != testProtoName {
		t.Fatal("Not correct translation from ID to String")
	}
}

// This makes h2 the leader, so it creates a tree and entity list
// and start a protocol. H1 should receive that message and request the entity
// list and the treelist and then instantiate the protocol.
func TestProtocolAutomaticInstantiation(t *testing.T) {
	var simpleProto = "simpleAI"

	// setup
	chanH1 := make(chan bool)
	chanH2 := make(chan bool)
	chans := []chan bool{chanH1, chanH2}
	id := 0
	// custom creation function so we know the step due to the channels
	fn := func(n *TreeNodeInstance) (ProtocolInstance, error) {
		ps := SimpleProtocol{
			TreeNodeInstance: n,
			Chan:             chans[id],
		}
		log.ErrFatal(ps.RegisterHandler(ps.ReceiveMessage))
		id++
		return &ps, nil
	}

	GlobalProtocolRegister(simpleProto, fn)
	local := NewLocalTest()
	defer local.CloseAll()
	h, _, tree := local.GenTree(2, true)
	h1 := h[0]
	// start the protocol
	go func() {
		_, err := h1.StartProtocol(simpleProto, tree)
		if err != nil {
			t.Fatal(fmt.Sprintf("Could not start protocol %v", err))
		}
	}()

	// we are supposed to receive something from host1 from Start()
	<-chanH1

	// Then we are supposed to receive from h2 after he got the tree and the
	// entity list from h1
	<-chanH2
}

func TestProtocolError(t *testing.T) {
	var simpleProto = "simplePE"
	done := make(chan bool)
	// The simplePE-protocol sends a message from the root to its
	// children, which sends a message back and returns an error.
	// When the root receives the message back, the second message
	// is sent through the 'done'-channel. Like this we're sure that
	// the children-message-handler had the time to return an error.
	var protocolError error
	fn := func(n *TreeNodeInstance) (ProtocolInstance, error) {
		ps := SimpleProtocol{
			TreeNodeInstance: n,
			Chan:             done,
		}
		ps.Error = protocolError
		log.ErrFatal(ps.RegisterHandler(ps.ReturnError))
		return &ps, nil
	}

	GlobalProtocolRegister(simpleProto, fn)
	local := NewLocalTest()
	h, _, tree := local.GenTree(2, true)
	h1 := h[0]

	oldlvl := log.DebugVisible()
	// The error won't show if the DebugVisible is < 1
	if oldlvl < 1 {
		log.SetDebugVisible(1)
	}
	// Redirecting stderr, so we can catch the error
	log.OutputToBuf()

	// start the protocol
	go func() {
		_, err := h1.StartProtocol(simpleProto, tree)
		if err != nil {
			t.Fatal(fmt.Sprintf("Could not start protocol %v", err))
		}
	}()
	// Start is finished
	<-done
	// Return message is received
	<-done
	assert.Equal(t, "", log.GetStdErr(), "This should yield no error")

	protocolError = errors.New("Protocol Error")
	// start the protocol
	go func() {
		_, err := h1.StartProtocol(simpleProto, tree)
		if err != nil {
			t.Fatal(fmt.Sprintf("Could not start protocol %v", err))
		}
	}()
	// Start is finished
	<-done
	// Return message is received
	<-done
	local.CloseAll()

	str := log.GetStdErr()
	assert.NotEqual(t, "", str, "No error output")
	log.OutputToOs()

	log.SetDebugVisible(oldlvl)
}

func TestMessageProxyFactory(t *testing.T) {
	defer eraseAllMessageProxy()
	RegisterMessageProxy(NewTestMessageProxyChan)
	assert.True(t, len(messageProxyFactory.factories) == 1)
}

func TestMessageProxyStore(t *testing.T) {
	defer eraseAllMessageProxy()
	local := NewLocalTest()
	defer local.CloseAll()

	RegisterMessageProxy(NewTestMessageProxy)
	GlobalProtocolRegister(testProtoIOName, newTestProtocolInstance)
	h, _, tree := local.GenTree(2, true)

	go func() {
		// first time to wrap
		res := <-chanProtoIOFeedback
		require.Equal(t, "", res)
		// second time to unwrap
		res = <-chanProtoIOFeedback
		require.Equal(t, "", res)

	}()
	_, err := h[0].StartProtocol(testProtoIOName, tree)
	require.Nil(t, err)

	res := <-chanTestProtoInstance
	assert.True(t, res)
}

// MessageProxy part
var chanProtoIOCreation = make(chan bool)
var chanProtoIOFeedback = make(chan string)

const testProtoIOName = "TestIO"

type OuterPacket struct {
	Info  *OverlayMsg
	Inner *SimpleMessage
}

var OuterPacketType = network.RegisterMessage(OuterPacket{})

type TestMessageProxy struct{}

func NewTestMessageProxyChan() MessageProxy {
	chanProtoIOCreation <- true
	return &TestMessageProxy{}
}

func NewTestMessageProxy() MessageProxy {
	return &TestMessageProxy{}
}

func eraseAllMessageProxy() {
	messageProxyFactory.factories = nil
}

func (t *TestMessageProxy) Wrap(msg interface{}, info *OverlayMsg) (interface{}, error) {
	outer := &OuterPacket{}
	inner, ok := msg.(*SimpleMessage)
	if !ok {
		chanProtoIOFeedback <- "wrong message type in wrap"
	}
	outer.Inner = inner
	outer.Info = info
	chanProtoIOFeedback <- ""
	return outer, nil
}

func (t *TestMessageProxy) Unwrap(msg interface{}) (interface{}, *OverlayMsg, error) {
	if msg == nil {
		chanProtoIOFeedback <- "message nil!"
		return nil, nil, errors.New("message nil")
	}

	real, ok := msg.(*OuterPacket)
	if !ok {
		chanProtoIOFeedback <- "wrong type of message in unwrap"
		return nil, nil, errors.New("wrong message")
	}
	chanProtoIOFeedback <- ""
	return real.Inner, real.Info, nil
}

func (t *TestMessageProxy) PacketType() network.MessageTypeID {
	return OuterPacketType
}

func (t *TestMessageProxy) Name() string {
	return testProtoIOName
}

var chanTestProtoInstance = make(chan bool)

// ProtocolInstance part
type TestProtocolInstance struct {
	*TreeNodeInstance
}

func newTestProtocolInstance(n *TreeNodeInstance) (ProtocolInstance, error) {
	pi := &TestProtocolInstance{n}
	n.RegisterHandler(pi.handleSimpleMessage)
	return pi, nil
}

func (t *TestProtocolInstance) Start() error {
	t.SendTo(t.Root(), &SimpleMessage{12})
	return nil
}

type SimpleMessageHandler struct {
	*TreeNode
	SimpleMessage
}

func (t TestProtocolInstance) handleSimpleMessage(h SimpleMessageHandler) error {
	chanTestProtoInstance <- h.SimpleMessage.I == 12
	return nil
}
