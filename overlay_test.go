package onet

import (
	"testing"

	"github.com/dedis/onet/network"
	"github.com/satori/go.uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type ProtocolOverlay struct {
	*TreeNodeInstance
	done bool
}

func (po *ProtocolOverlay) Start() error {
	// no need to do anything
	return nil
}

func (po *ProtocolOverlay) Dispatch() error {
	return nil
}

func (po *ProtocolOverlay) Release() {
	// call the Done function
	po.Done()
}

func TestOverlayDone(t *testing.T) {
	// setup
	fn := func(n *TreeNodeInstance) (ProtocolInstance, error) {
		ps := ProtocolOverlay{
			TreeNodeInstance: n,
		}
		return &ps, nil
	}
	GlobalProtocolRegister("ProtocolOverlay", fn)
	local := NewLocalTest()
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
	local := NewLocalTest()
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
	local := NewLocalTest()
	hosts, el, _ := local.GenTree(2, false)
	defer local.CloseAll()
	h1 := hosts[0]
	h2 := hosts[1]
	proc := newOverlayProc()
	h1.RegisterProcessor(proc, proc.Types()...)

	// Check that h2 sends back an empty list if it is unknown
	err := h1.Send(h2.ServerIdentity, &RequestRoster{
		RosterID: el.ID})
	if err != nil {
		t.Fatal("Couldn't send message to h2:", err)
	}
	roster := <-proc.sendRoster
	if roster.ID != RosterID(uuid.Nil) {
		t.Fatal("List should be empty")
	}

	// Now add the list to h2 and try again
	h2.AddRoster(el)
	err = h1.Send(h2.ServerIdentity, &RequestRoster{RosterID: el.ID})
	if err != nil {
		t.Fatal("Couldn't send message to h2:", err)
	}
	msg := <-proc.sendRoster
	if msg.ID != el.ID {
		t.Fatal("List should be equal to original list")
	}

	err = h1.Send(h2.ServerIdentity, &RequestRoster{RosterID: el.ID})
	if err != nil {
		t.Fatal("Couldn't send message to h2:", err)
	}
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
	local := NewLocalTest()
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
	err := h1.Send(h2.ServerIdentity, &RequestTree{TreeID: tree.ID})
	if err != nil {
		t.Fatal("Couldn't send message to h2:", err)
	}
	msg := <-proc.treeMarshal
	if msg.RosterID != RosterID(uuid.Nil) {
		t.Fatal("List should be empty")
	}

	// Now add the list to h2 and try again
	h2.AddTree(tree)
	err = h1.Send(h2.ServerIdentity, &RequestTree{TreeID: tree.ID})
	require.Nil(t, err)

	msg = <-proc.treeMarshal
	assert.Equal(t, msg.TreeID, tree.ID)

	err = h1.Send(h2.ServerIdentity, &RequestTree{TreeID: tree.ID})
	require.Nil(t, err)
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
	local := NewLocalTest()
	hosts, el, tree := local.GenTree(2, false)
	defer local.CloseAll()
	h1 := hosts[0]
	h2 := hosts[1]

	// h2 knows the entity list
	h2.AddRoster(el)
	// and the tree
	h2.AddTree(tree)
	// make the communcation happen
	if err := h1.Send(h2.ServerIdentity, &RequestTree{TreeID: tree.ID}); err != nil {
		t.Fatal("Could not send tree request to host2", err)
	}

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
	if uuid.Equal(uuid.UUID(id1), uuid.UUID(id2)) {
		t.Fatal("Both token are the same")
	}
	if !uuid.Equal(uuid.UUID(id1), uuid.UUID(t1.ID())) {
		t.Fatal("Twice the Id of the same token should be equal")
	}
	t3 := t1.ChangeTreeNodeID(TreeNodeID(uuid.NewV1()))
	if t1.TreeNodeID.Equal(t3.TreeNodeID) {
		t.Fatal("OtherToken should modify copy")
	}
}
