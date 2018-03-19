package onet

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/dedis/onet.v2/log"
	"gopkg.in/dedis/onet.v2/network"
	"gopkg.in/satori/go.uuid.v1"
)

// A checkableError is a type that implements error and also lets
// you find out, by reading on a channel, how many times it has been
// formatted using Error().
type checkableError struct {
	ch  chan struct{}
	msg string
}

func (ce *checkableError) Error() string {
	ce.ch <- struct{}{}
	return ce.msg
}

var dispFailErr = &checkableError{
	ch:  make(chan struct{}, 10),
	msg: "Dispatch failed",
}

type ProtocolOverlay struct {
	*TreeNodeInstance
	done         bool
	failDispatch bool
	failChan     chan bool
}

func (po *ProtocolOverlay) Start() error {
	// no need to do anything
	return nil
}

func (po *ProtocolOverlay) Dispatch() error {
	if po.failDispatch {
		return dispFailErr
	}
	return nil
}

func (po *ProtocolOverlay) Release() {
	// call the Done function
	po.Done()
}

func TestOverlayDispatchFailure(t *testing.T) {
	log.OutputToBuf()
	defer log.OutputToOs()

	// setup
	failChan := make(chan bool, 1)
	fn := func(n *TreeNodeInstance) (ProtocolInstance, error) {
		ps := ProtocolOverlay{
			TreeNodeInstance: n,
			failDispatch:     true,
			failChan:         failChan,
		}
		return &ps, nil
	}
	GlobalProtocolRegister("ProtocolOverlay", fn)
	local := NewLocalTest(tSuite)
	defer local.CloseAll()
	h, _, tree := local.GenTree(1, true)
	h1 := h[0]
	_, err := h1.CreateProtocol("ProtocolOverlay", tree)
	if err != nil {
		t.Fatal("error starting new node", err)
	}

	// wait for the error message to get formatted by overlay.go
	<-dispFailErr.ch

	// when using `go test -v`, the error string goes into the stderr buffer
	// but with `go test`, it goes into the stdout buffer, so we check both
	assert.Contains(t, log.GetStdOut()+log.GetStdErr(), "Dispatch failed")
}

func TestOverlayDone(t *testing.T) {
	log.OutputToBuf()
	defer log.OutputToOs()

	// setup
	fn := func(n *TreeNodeInstance) (ProtocolInstance, error) {
		ps := ProtocolOverlay{
			TreeNodeInstance: n,
		}
		return &ps, nil
	}
	GlobalProtocolRegister("ProtocolOverlay", fn)
	local := NewLocalTest(tSuite)
	defer local.CloseAll()
	h, _, tree := local.GenTree(1, true)
	h1 := h[0]
	p, err := h1.CreateProtocol("ProtocolOverlay", tree)
	if err != nil {
		t.Fatal("error starting new node", err)
	}
	po := p.(*ProtocolOverlay)
	// release the resources
	var count int
	po.OnDoneCallback(func() bool {
		count++
		if count >= 2 {
			return true
		}
		return false
	})
	po.Release()
	overlay := h1.overlay
	if _, ok := overlay.TokenToNode(po.Token()); !ok {
		t.Fatal("Node should exists after first call Done()")
	}
	po.Release()
	if _, ok := overlay.TokenToNode(po.Token()); ok {
		t.Fatal("Node should NOT exists after call Done()")
	}
}

// Test when a peer receives a New Roster, it can create the trees that are
// waiting on this specific entitiy list, to be constructed.
func TestOverlayPendingTreeMarshal(t *testing.T) {
	local := NewLocalTest(tSuite)
	hosts, el, tree := local.GenTree(2, false)
	defer local.CloseAll()
	h1 := hosts[0]

	// Add the marshalled version of the tree
	local.addPendingTreeMarshal(h1, tree.MakeTreeMarshal())
	if _, ok := h1.GetTree(tree.ID); ok {
		t.Fatal("host 1 should not have the tree definition yet.")
	}
	// Now make it check
	local.checkPendingTreeMarshal(h1, el)
	if _, ok := h1.GetTree(tree.ID); !ok {
		t.Fatal("Host 1 should have the tree definition now.")
	}
}

// overlayProc is a Processor which handles the management packet of Overlay,
// i.e. Roster & Tree management.
// Each type of message will be sent trhough the appropriate channel
type overlayProc struct {
	sendRoster  chan *Roster
	treeMarshal chan *TreeMarshal
	requestTree chan *RequestTree
}

func newOverlayProc() *overlayProc {
	return &overlayProc{
		sendRoster:  make(chan *Roster, 1),
		treeMarshal: make(chan *TreeMarshal, 1),
		requestTree: make(chan *RequestTree, 1),
	}
}

func (op *overlayProc) Process(env *network.Envelope) {
	switch env.MsgType {
	case SendRosterMsgID:
		op.sendRoster <- env.Msg.(*Roster)
	case TreeMarshalTypeID:
		op.treeMarshal <- env.Msg.(*TreeMarshal)
	case RequestTreeMsgID:
		op.requestTree <- env.Msg.(*RequestTree)
	}
}

func (op *overlayProc) Types() []network.MessageTypeID {
	return []network.MessageTypeID{SendRosterMsgID, TreeMarshalTypeID}
}

// Test propagation of roster - both known and unknown
func TestOverlayRosterPropagation(t *testing.T) {
	local := NewLocalTest(tSuite)
	hosts, el, _ := local.GenTree(2, false)
	defer local.CloseAll()
	h1 := hosts[0]
	h2 := hosts[1]
	proc := newOverlayProc()
	h1.RegisterProcessor(proc, proc.Types()...)

	// Check that h2 sends back an empty list if it is unknown
	sentLen, err := h1.Send(h2.ServerIdentity, &RequestRoster{
		RosterID: el.ID})
	require.Nil(t, err, "Couldn't send message to h1")
	require.NotZero(t, sentLen)

	roster := <-proc.sendRoster
	if !roster.ID.IsNil() {
		t.Fatal("List should be empty")
	}

	// Now add the list to h2 and try again
	h2.AddRoster(el)
	sentLen, err = h1.Send(h2.ServerIdentity, &RequestRoster{RosterID: el.ID})
	require.Nil(t, err, "Couldn't send message to h2")
	require.NotZero(t, sentLen)

	msg := <-proc.sendRoster
	if !msg.ID.Equal(el.ID) {
		t.Fatal("List should be equal to original list")
	}

	sentLen, err = h1.Send(h2.ServerIdentity, &RequestRoster{RosterID: el.ID})
	require.Nil(t, err, "Couldn't send message to h2")
	require.NotZero(t, sentLen)

	// check if we receive the Roster then
	ros := <-proc.sendRoster
	packet := network.Envelope{
		ServerIdentity: h2.ServerIdentity,
		Msg:            ros,
		MsgType:        SendRosterMsgID,
	}
	h1.overlay.Process(&packet)
	list, ok := h1.Roster(el.ID)
	assert.True(t, ok)
	assert.Equal(t, list.ID, el.ID)
}

// Test propagation of tree - both known and unknown
func TestOverlayTreePropagation(t *testing.T) {
	local := NewLocalTest(tSuite)
	hosts, el, tree := local.GenTree(2, false)
	defer local.CloseAll()
	h1 := hosts[0]
	h2 := hosts[1]
	// Suppose both hosts have the list available, but not the tree
	h1.AddRoster(el)
	h2.AddRoster(el)

	proc := newOverlayProc()
	h1.RegisterProcessor(proc, SendTreeMsgID)
	//h2.RegisterProcessor(proc, proc.Types()...)

	// Check that h2 sends back an empty tree if it is unknown
	sentLen, err := h1.Send(h2.ServerIdentity, &RequestTree{TreeID: tree.ID})
	require.Nil(t, err, "Couldn't send message to h2")
	require.NotZero(t, sentLen)

	msg := <-proc.treeMarshal
	if !msg.RosterID.IsNil() {
		t.Fatal("List should be empty")
	}

	// Now add the list to h2 and try again
	h2.AddTree(tree)
	sentLen, err = h1.Send(h2.ServerIdentity, &RequestTree{TreeID: tree.ID})
	require.Nil(t, err)
	require.NotZero(t, sentLen)

	msg = <-proc.treeMarshal
	assert.Equal(t, msg.TreeID, tree.ID)

	sentLen, err = h1.Send(h2.ServerIdentity, &RequestTree{TreeID: tree.ID})
	require.Nil(t, err)
	require.NotZero(t, sentLen)

	// check if we receive the tree then
	var tm *TreeMarshal
	tm = <-proc.treeMarshal
	packet := network.Envelope{
		ServerIdentity: h2.ServerIdentity,
		Msg:            tm,
		MsgType:        SendTreeMsgID,
	}
	h1.overlay.Process(&packet)

	tree2, ok := h1.GetTree(tree.ID)
	if !ok {
		t.Fatal("List-id not found")
	}
	if !tree.Equal(tree2) {
		t.Fatal("Trees do not match")
	}
}

// Tests both list- and tree-propagation
// basically h1 ask for a tree id
// h2 respond with the tree
// h1 ask for the entitylist (because it dont know)
// h2 respond with the entitylist
func TestOverlayRosterTreePropagation(t *testing.T) {
	local := NewLocalTest(tSuite)
	hosts, el, tree := local.GenTree(2, false)
	defer local.CloseAll()
	h1 := hosts[0]
	h2 := hosts[1]

	// h2 knows the entity list
	h2.AddRoster(el)
	// and the tree
	h2.AddTree(tree)
	// make the communcation happen
	sentLen, err := h1.Send(h2.ServerIdentity, &RequestTree{TreeID: tree.ID})
	require.Nil(t, err, "Could not send tree request to host2")
	require.NotZero(t, sentLen)

	proc := newOverlayProc()
	h1.RegisterProcessor(proc, SendRosterMsgID)
	h1.RegisterProcessor(proc, SendTreeMsgID)

	// check if we have the tree
	treeM := <-proc.treeMarshal

	packet := network.Envelope{
		ServerIdentity: h2.ServerIdentity,
		Msg:            treeM,
		MsgType:        SendTreeMsgID,
	}
	// give it to overlay
	h1.overlay.Process(&packet)
	// the tree should not be there because we don't have the Roster associated
	// yet
	if _, ok := h1.GetTree(tree.ID); ok {
		t.Fatal("Tree should Not be there")
	}
	// check if we receive the Roster then
	roster := <-proc.sendRoster

	packet = network.Envelope{
		ServerIdentity: h2.ServerIdentity,
		Msg:            roster,
		MsgType:        SendRosterMsgID,
	}
	h1.overlay.Process(&packet)

	// check if we have the roster now  & the tree
	if _, ok := h1.Roster(el.ID); !ok {
		t.Fatal("Roster should be here")
	}
	if _, ok := h1.GetTree(tree.ID); !ok {
		t.Fatal("Tree should be there")
	}
}

func TestTokenId(t *testing.T) {
	t1 := &Token{
		RosterID: RosterID(uuid.NewV1()),
		TreeID:   TreeID(uuid.NewV1()),
		ProtoID:  ProtocolID(uuid.NewV1()),
		RoundID:  RoundID(uuid.NewV1()),
	}
	id1 := t1.ID()
	t2 := &Token{
		RosterID: RosterID(uuid.NewV1()),
		TreeID:   TreeID(uuid.NewV1()),
		ProtoID:  ProtocolID(uuid.NewV1()),
		RoundID:  RoundID(uuid.NewV1()),
	}
	id2 := t2.ID()
	if id1.Equal(id2) {
		t.Fatal("Both token are the same")
	}
	if !id1.Equal(t1.ID()) {
		t.Fatal("Twice the Id of the same token should be equal")
	}
	t3 := t1.ChangeTreeNodeID(TreeNodeID(uuid.NewV1()))
	if t1.TreeNodeID.Equal(t3.TreeNodeID) {
		t.Fatal("OtherToken should modify copy")
	}
}
