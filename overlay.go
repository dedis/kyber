package onet

import (
	"errors"
	"fmt"
	"sync"

	"github.com/dedis/crypto/abstract"
	"github.com/dedis/onet/log"
	"github.com/dedis/onet/network"
	"github.com/satori/go.uuid"
)

// Overlay keeps all trees and entity-lists for a given Conode. It creates
// Nodes and ProtocolInstances upon request and dispatches the messages.
type Overlay struct {
	conode *Conode
	// mapping from Tree.Id to Tree
	trees    map[TreeID]*Tree
	treesMut sync.Mutex
	// mapping from Roster.id to Roster
	entityLists    map[RosterID]*Roster
	entityListLock sync.Mutex
	// cache for relating token(~Node) to TreeNode
	cache *TreeNodeCache

	// TreeNodeInstance part
	instances         map[TokenID]*TreeNodeInstance
	instancesInfo     map[TokenID]bool
	instancesLock     sync.Mutex
	protocolInstances map[TokenID]ProtocolInstance

	// treeMarshal that needs to be converted to Tree but host does not have the
	// entityList associated yet.
	// map from Roster.ID => trees that use this entity list
	pendingTreeMarshal map[RosterID][]*TreeMarshal
	// lock associated with pending TreeMarshal
	pendingTreeLock sync.Mutex

	// pendingMsg is a list of message we received that does not correspond
	// to any local Tree or/and Roster. We first request theses so we can
	// instantiate properly protocolInstance that will use these ProtocolMsg msg.
	pendingMsg []pendingMsg
	// lock associated with pending ProtocolMsg
	pendingMsgLock sync.Mutex

	transmitMux sync.Mutex

	protoIO *messageProxyStore

	pendingConfigs    map[TokenID]*GenericConfig
	pendingConfigsMut sync.Mutex
}

// NewOverlay creates a new overlay-structure
func NewOverlay(c *Conode) *Overlay {
	o := &Overlay{
		conode:             c,
		trees:              make(map[TreeID]*Tree),
		entityLists:        make(map[RosterID]*Roster),
		cache:              NewTreeNodeCache(),
		instances:          make(map[TokenID]*TreeNodeInstance),
		instancesInfo:      make(map[TokenID]bool),
		protocolInstances:  make(map[TokenID]ProtocolInstance),
		pendingTreeMarshal: make(map[RosterID][]*TreeMarshal),
		pendingConfigs:     make(map[TokenID]*GenericConfig),
	}
	o.protoIO = newMessageProxyStore(c, o)
	// messages going to protocol instances
	c.RegisterProcessor(o,
		ProtocolMsgID,          // protocol instance's messages
		RequestTreeMessageID,   // request a tree
		SendTreeMessageID,      // send a tree back to a request
		RequestRosterMessageID, // request a roster
		SendRosterMessageID,    // send a roster back to request
		ConfigMessageID)        // fetch config information
	return o
}

// Process implements the Processor interface so it process the messages that it
// wants.
func (o *Overlay) Process(data *network.Packet) {
	// Messages handled by the overlay directly without any messageProxyIO
	if data.MsgType == ConfigMessageID {
		o.handleConfigMessage(data)
		return
	}

	// get messageProxy or default one
	io := o.protoIO.getByPacketType(data.MsgType)
	inner, info, err := io.Unwrap(data.Msg)
	if err != nil {
		log.Error("unwrapping: ", err)
		return
	}
	switch true {
	case info.RequestTree != nil:
		o.handleRequestTree(data.ServerIdentity, info.RequestTree, io)
	case info.TreeMarshal != nil:
		o.handleSendTree(data.ServerIdentity, info.TreeMarshal, io)
	case info.RequestRoster != nil:
		o.handleRequestRoster(data.ServerIdentity, info.RequestRoster, io)
	case info.Roster != nil:
		o.handleSendRoster(data.ServerIdentity, info.Roster)
	default:
		typ := network.TypeToPacketTypeID(inner)
		protoMsg := &ProtocolMsg{
			From:           info.TreeNodeInfo.From,
			To:             info.TreeNodeInfo.To,
			ServerIdentity: data.ServerIdentity,
			Msg:            inner,
			MsgType:        typ,
		}
		o.TransmitMsg(protoMsg, io)
	}
}

// TransmitMsg takes a message received from the host and treats it. It might
// - ask for the identityList
// - ask for the Tree
// - create a new protocolInstance
// - pass it to a given protocolInstance
// io is the messageProxy to use if a specific wireformat protocol is used.
// It can be nil: in that case it fall backs to default wire protocol.
func (o *Overlay) TransmitMsg(onetMsg *ProtocolMsg, io MessageProxy) error {
	tree := o.Tree(onetMsg.To.TreeID)
	if tree == nil {
		return o.requestTree(onetMsg.ServerIdentity, onetMsg, io)
	}

	o.transmitMux.Lock()
	defer o.transmitMux.Unlock()
	// TreeNodeInstance
	var pi ProtocolInstance
	o.instancesLock.Lock()
	pi, ok := o.protocolInstances[onetMsg.To.ID()]
	done := o.instancesInfo[onetMsg.To.ID()]
	o.instancesLock.Unlock()
	if done {
		log.Error("Message for TreeNodeInstance that is already finished")
		return nil
	}
	// if the TreeNodeInstance is not there, creates it
	if !ok {
		log.Lvlf4("Creating TreeNodeInstance at %s %x", o.conode.ServerIdentity, onetMsg.To.ID())
		tn, err := o.TreeNodeFromToken(onetMsg.To)
		if err != nil {
			return errors.New("No TreeNode defined in this tree here")
		}
		tni := o.newTreeNodeInstanceFromToken(tn, onetMsg.To, io)
		// retrieve the possible generic config for this message
		config := o.getConfig(onetMsg.To.ID())
		// request the PI from the Service and binds the two
		pi, err = o.conode.serviceManager.newProtocol(tni, config)
		if err != nil {
			return err
		}
		if pi == nil {
			return nil
		}
		go pi.Dispatch()
		if err := o.RegisterProtocolInstance(pi); err != nil {
			return errors.New("Error Binding TreeNodeInstance and ProtocolInstance:" +
				err.Error())
		}
		log.Lvl4(o.conode.Address(), "Overlay created new ProtocolInstace msg => ",
			fmt.Sprintf("%+v", onetMsg.To))
	}
	// TODO Check if TreeNodeInstance is already Done
	pi.ProcessProtocolMsg(onetMsg)
	return nil
}

// addPendingTreeMarshal adds a treeMarshal to the list.
// This list is checked each time we receive a new Roster
// so trees using this Roster can be constructed.
func (o *Overlay) addPendingTreeMarshal(tm *TreeMarshal) {
	o.pendingTreeLock.Lock()
	var sl []*TreeMarshal
	var ok bool
	// initiate the slice before adding
	if sl, ok = o.pendingTreeMarshal[tm.RosterID]; !ok {
		sl = make([]*TreeMarshal, 0)
	}
	sl = append(sl, tm)
	o.pendingTreeMarshal[tm.RosterID] = sl
	o.pendingTreeLock.Unlock()
}

// checkPendingMessages is called each time we receive a new tree if there are
// some pending ProtocolMessage messages using this tree. If there are, we can
// make an instance of a protocolinstance and give it the message.
func (o *Overlay) checkPendingMessages(t *Tree) {
	go func() {
		o.pendingMsgLock.Lock()
		var newPending []pendingMsg
		for _, pending := range o.pendingMsg {
			if t.ID.Equals(pending.ProtocolMsg.To.TreeID) {
				// if this message references t, instantiate it and go
				err := o.TransmitMsg(pending.ProtocolMsg, pending.MessageProxy)
				if err != nil {
					log.Error("TransmitMsg failed:", err)
					continue
				}
			} else {
				newPending = append(newPending, pending)
			}
		}
		o.pendingMsg = newPending
		o.pendingMsgLock.Unlock()
	}()
}

// checkPendingTreeMarshal is called each time we add a new Roster to the
// system. It checks if some treeMarshal use this entityList so they can be
// converted to Tree.
func (o *Overlay) checkPendingTreeMarshal(el *Roster) {
	o.pendingTreeLock.Lock()
	sl, ok := o.pendingTreeMarshal[el.ID]
	if !ok {
		// no tree for this entitty list
		return
	}
	for _, tm := range sl {
		tree, err := tm.MakeTree(el)
		if err != nil {
			log.Error("Tree from Roster failed")
			continue
		}
		// add the tree into our "database"
		o.RegisterTree(tree)
	}
	o.pendingTreeLock.Unlock()
}

func (o *Overlay) savePendingMsg(onetMsg *ProtocolMsg, io MessageProxy) {
	o.pendingMsgLock.Lock()
	o.pendingMsg = append(o.pendingMsg, pendingMsg{
		ProtocolMsg:  onetMsg,
		MessageProxy: io,
	})
	o.pendingMsgLock.Unlock()

}

// requestTree will ask for the tree the ProtocolMessage is related to.
// it will put the message inside the pending list of ProtocolMessage waiting to
// have their trees.
// io is the wrapper to use to send the message, it can be nil.
func (o *Overlay) requestTree(si *network.ServerIdentity, onetMsg *ProtocolMsg, io MessageProxy) error {
	o.savePendingMsg(onetMsg, io)

	var msg interface{}
	om := &OverlayMessage{
		RequestTree: &RequestTree{onetMsg.To.TreeID},
	}
	msg, err := io.Wrap(nil, om)
	if err != nil {
		return err
	}

	err = o.conode.Send(si, msg)
	return err
}

// RegisterTree takes a tree and puts it in the map
func (o *Overlay) RegisterTree(t *Tree) {
	o.treesMut.Lock()
	o.trees[t.ID] = t
	o.treesMut.Unlock()
	o.checkPendingMessages(t)
}

// TreeFromToken searches for the tree corresponding to a token.
func (o *Overlay) TreeFromToken(tok *Token) *Tree {
	o.treesMut.Lock()
	defer o.treesMut.Unlock()
	return o.trees[tok.TreeID]
}

// Tree returns the tree given by treeId or nil if not found
func (o *Overlay) Tree(tid TreeID) *Tree {
	o.treesMut.Lock()
	defer o.treesMut.Unlock()
	return o.trees[tid]
}

// RegisterRoster puts an entityList in the map
func (o *Overlay) RegisterRoster(el *Roster) {
	o.entityListLock.Lock()
	defer o.entityListLock.Unlock()
	o.entityLists[el.ID] = el
}

// RosterFromToken returns the entitylist corresponding to a token
func (o *Overlay) RosterFromToken(tok *Token) *Roster {
	return o.entityLists[tok.RosterID]
}

// Roster returns the entityList given by RosterID
func (o *Overlay) Roster(elid RosterID) *Roster {
	o.entityListLock.Lock()
	defer o.entityListLock.Unlock()
	return o.entityLists[elid]
}

// TreeNodeFromToken returns the treeNode corresponding to a token
func (o *Overlay) TreeNodeFromToken(t *Token) (*TreeNode, error) {
	if t == nil {
		return nil, errors.New("didn't find tree-node: No token given")
	}
	// First, check the cache
	if tn := o.cache.GetFromToken(t); tn != nil {
		return tn, nil
	}
	// If cache has not, then search the tree
	tree := o.Tree(t.TreeID)
	if tree == nil {
		return nil, errors.New("didn't find tree")
	}
	tn := tree.Search(t.TreeNodeID)
	if tn == nil {
		return nil, errors.New("didn't find treenode")
	}
	// Since we found treeNode, cache it so later reuse
	o.cache.Cache(tree, tn)
	return tn, nil
}

func (o *Overlay) handleRequestTree(si *network.ServerIdentity, req *RequestTree, io MessageProxy) {
	tid := req.TreeID
	tree := o.Tree(tid)
	var err error
	var treeM *TreeMarshal
	var msg interface{}
	if tree != nil {
		treeM = tree.MakeTreeMarshal()
	} else {
		// XXX Take care here for we must verify at the other side that
		// the tree is Nil. Should we think of a way of sending back an
		// "error" ?
		treeM = (&Tree{}).MakeTreeMarshal()
	}
	msg, err = io.Wrap(nil, &OverlayMessage{
		TreeMarshal: treeM,
	})

	if err != nil {
		log.Error("couldn't wrap TreeMarshal:", err)
		return
	}

	err = o.conode.Send(si, msg)
	if err != nil {
		log.Error("Couldn't send tree:", err)
	}
}

func (o *Overlay) handleSendTree(si *network.ServerIdentity, tm *TreeMarshal, io MessageProxy) {
	if tm.TreeID == TreeID(uuid.Nil) {
		log.Error("Received an empty Tree")
		return
	}
	roster := o.Roster(tm.RosterID)
	// The roster does not exists, we should request that, too
	if roster == nil {
		msg, err := io.Wrap(nil, &OverlayMessage{
			RequestRoster: &RequestRoster{tm.RosterID},
		})
		if err != nil {
			log.Error("could not wrap RequestRoster:", err)
		}
		if err := o.conode.Send(si, msg); err != nil {
			log.Error("Requesting Roster in SendTree failed", err)
		}
		// put the tree marshal into pending queue so when we receive the
		// entitylist we can create the real Tree.
		o.addPendingTreeMarshal(tm)
		return
	}

	tree, err := tm.MakeTree(roster)
	if err != nil {
		log.Error("Couldn't create tree:", err)
		return
	}
	log.Lvl4("Received new tree")
	o.RegisterTree(tree)
}

func (o *Overlay) handleRequestRoster(si *network.ServerIdentity, req *RequestRoster, io MessageProxy) {
	id := req.RosterID
	roster := o.Roster(id)
	var err error
	var msg interface{}
	if roster == nil {
		// XXX Bad reaction to request...
		log.Lvl2("Requested entityList that we don't have")
		roster = &Roster{}
	}

	msg, err = io.Wrap(nil, &OverlayMessage{
		Roster: roster,
	})

	if err != nil {
		log.Error("error wraping up roster:", err)
		return
	}

	err = o.conode.Send(si, msg)
	if err != nil {
		log.Error("Couldn't send empty entity list from host:",
			o.conode.ServerIdentity.String(),
			err)
		return
	}
}

func (o *Overlay) handleSendRoster(si *network.ServerIdentity, roster *Roster) {
	if roster.ID == RosterID(uuid.Nil) {
		log.Lvl2("Received an empty Roster")
	} else {
		o.RegisterRoster(roster)
		// Check if some trees can be constructed from this entitylist
		o.checkPendingTreeMarshal(roster)
	}
	log.Lvl4("Received new entityList")
}

// handleConfigMessage stores the config message so it can be dispatched
// alongside with the protocol message later to the service.
func (o *Overlay) handleConfigMessage(data *network.Packet) {
	config, ok := data.Msg.(ConfigMessage)
	if !ok {
		// This should never happen <=> assert
		log.Panic(o.conode.Address(), "wrong config type")
		return
	}

	o.pendingConfigsMut.Lock()
	defer o.pendingConfigsMut.Unlock()
	o.pendingConfigs[config.Dest] = &config.Config
}

// getConfig returns the generic config corresponding to this node if present,
// and removes it from the list of pending configs.
func (o *Overlay) getConfig(id TokenID) *GenericConfig {
	o.pendingConfigsMut.Lock()
	defer o.pendingConfigsMut.Unlock()
	c := o.pendingConfigs[id]
	delete(o.pendingConfigs, id)
	return c
}

// SendToTreeNode sends a message to a treeNode
// from is the sender token
// to is the treenode of the destination
// msg is the message to send
// io is the messageproxy used to correctly create the wire format
// c is the generic config that should be sent beforehand in order to get passed
// in the `NewProtocol` method if a Service has created the protocol and set the
// config with `SetConfig`. It can be nil.
func (o *Overlay) SendToTreeNode(from *Token, to *TreeNode, msg network.Body,
	io MessageProxy, c *GenericConfig) error {
	tokenTo := from.ChangeTreeNodeID(to.ID)

	// first send the config if present
	if c != nil {
		if err := o.conode.Send(to.ServerIdentity, &ConfigMessage{*c, tokenTo.ID()}); err != nil {
			log.Error("sending config failed:", err)
			return err
		}
	}
	// then send the message
	var final interface{}
	info := &OverlayMessage{
		TreeNodeInfo: &TreeNodeInfo{
			From: from,
			To:   tokenTo,
		},
	}
	final, err := io.Wrap(msg, info)
	if err != nil {
		return err
	}
	return o.conode.Send(to.ServerIdentity, final)
}

// nodeDone is called by node to signify that its work is finished and its
// ressources can be released
func (o *Overlay) nodeDone(tok *Token) {
	o.instancesLock.Lock()
	defer o.instancesLock.Unlock()
	o.nodeDelete(tok)
}

// nodeDelete needs to be separated from nodeDone, as it is also called from
// Close, but due to locking-issues here we don't lock.
func (o *Overlay) nodeDelete(tok *Token) {
	tni, ok := o.instances[tok.ID()]
	if !ok {
		log.Lvlf2("Node %x already gone", tok.ID())
		return
	}
	log.Lvl4("Closing node", tok.ID())
	err := tni.Close()
	if err != nil {
		log.Error("Error while closing node:", err)
	}
	delete(o.instances, tok.ID())
	// mark it done !
	o.instancesInfo[tok.ID()] = true
}

func (o *Overlay) suite() abstract.Suite {
	return o.conode.Suite()
}

// Close calls all nodes, deletes them from the list and closes them
func (o *Overlay) Close() {
	o.instancesLock.Lock()
	defer o.instancesLock.Unlock()
	for _, tni := range o.instances {
		log.Lvl4(o.conode.Address(), "Closing TNI", tni.TokenID())
		o.nodeDelete(tni.Token())
	}
}

// CreateProtocol creates a ProtocolInstance, registers it to the Overlay.
// Additionally, if sid is different than NilServiceID, sid is added to the token
// so the protocol will be picked up by the correct service and handled by its
// NewProtocol method. If the sid is NilServiceID, then the protoocol is handled by onet alone.
func (o *Overlay) CreateProtocol(name string, t *Tree, sid ServiceID) (ProtocolInstance, error) {
	io := o.protoIO.getByName(name)
	tni := o.NewTreeNodeInstanceFromService(t, t.Root, ProtocolNameToID(name), sid, io)
	pi, err := o.conode.protocolInstantiate(tni.token.ProtoID, tni)
	if err != nil {
		return nil, err
	}
	if err = o.RegisterProtocolInstance(pi); err != nil {
		return nil, err
	}
	go pi.Dispatch()
	return pi, err
}

// StartProtocol will create and start a ProtocolInstance.
func (o *Overlay) StartProtocol(name string, t *Tree, sid ServiceID) (ProtocolInstance, error) {
	pi, err := o.CreateProtocol(name, t, sid)
	if err != nil {
		return nil, err
	}
	go func() {
		err := pi.Start()
		if err != nil {
			log.Error("Error while starting:", err)
		}
	}()
	return pi, err
}

// NewTreeNodeInstanceFromProtoName takes a protocol name and a tree and
// instantiate a TreeNodeInstance for this protocol.
func (o *Overlay) NewTreeNodeInstanceFromProtoName(t *Tree, name string) *TreeNodeInstance {
	io := o.protoIO.getByName(name)
	return o.NewTreeNodeInstanceFromProtocol(t, t.Root, ProtocolNameToID(name), io)
}

// NewTreeNodeInstanceFromProtocol takes a tree and a treenode (normally the
// root) and and protocolID and returns a fresh TreeNodeInstance.
func (o *Overlay) NewTreeNodeInstanceFromProtocol(t *Tree, tn *TreeNode, protoID ProtocolID, io MessageProxy) *TreeNodeInstance {
	tok := &Token{
		TreeNodeID: tn.ID,
		TreeID:     t.ID,
		RosterID:   t.Roster.ID,
		ProtoID:    protoID,
		RoundID:    RoundID(uuid.NewV4()),
	}
	tni := o.newTreeNodeInstanceFromToken(tn, tok, io)
	o.RegisterTree(t)
	o.RegisterRoster(t.Roster)
	return tni
}

// NewTreeNodeInstanceFromService takes a tree, a TreeNode and a service ID and
// returns a TNI.
func (o *Overlay) NewTreeNodeInstanceFromService(t *Tree, tn *TreeNode, protoID ProtocolID, servID ServiceID, io MessageProxy) *TreeNodeInstance {
	tok := &Token{
		TreeNodeID: tn.ID,
		TreeID:     t.ID,
		RosterID:   t.Roster.ID,
		ProtoID:    protoID,
		ServiceID:  servID,
		RoundID:    RoundID(uuid.NewV4()),
	}
	tni := o.newTreeNodeInstanceFromToken(tn, tok, io)
	o.RegisterTree(t)
	o.RegisterRoster(t.Roster)
	return tni
}

// ServerIdentity Returns the entity of the Host
func (o *Overlay) ServerIdentity() *network.ServerIdentity {
	return o.conode.ServerIdentity
}

// newTreeNodeInstanceFromToken is to be called by the Overlay when it receives
// a message it does not have a treenodeinstance registered yet. The protocol is
// already running so we should *not* generate a new RoundID.
func (o *Overlay) newTreeNodeInstanceFromToken(tn *TreeNode, tok *Token, io MessageProxy) *TreeNodeInstance {
	tni := newTreeNodeInstance(o, tok, tn, io)
	o.instancesLock.Lock()
	defer o.instancesLock.Unlock()
	o.instances[tok.ID()] = tni
	return tni
}

// ErrWrongTreeNodeInstance is returned when you already binded a TNI with a PI.
var ErrWrongTreeNodeInstance = errors.New("This TreeNodeInstance doesn't exist")

// ErrProtocolRegistered is when the protocolinstance is already registered to
// the overlay
var ErrProtocolRegistered = errors.New("a ProtocolInstance already has been registered using this TreeNodeInstance")

// RegisterProtocolInstance takes a PI and stores it for dispatching the message
// to it.
func (o *Overlay) RegisterProtocolInstance(pi ProtocolInstance) error {
	o.instancesLock.Lock()
	defer o.instancesLock.Unlock()
	var tni *TreeNodeInstance
	var tok = pi.Token()
	var ok bool
	// if the TreeNodeInstance doesn't exist
	if tni, ok = o.instances[tok.ID()]; !ok {
		return ErrWrongTreeNodeInstance
	}

	if tni.isBound() {
		return ErrProtocolRegistered
	}

	tni.bind(pi)
	o.protocolInstances[tok.ID()] = pi
	log.Lvlf4("%s registered ProtocolInstance %x", o.conode.Address(), tok.ID())
	return nil
}

// pendingMsg is used to store messages destined for ProtocolInstances but when
// the tree designated is not known to the Overlay. When the tree is sent to the
// overlay, then the pendingMsg that are relying on this tree will get
// processed.
type pendingMsg struct {
	*ProtocolMsg
	MessageProxy
}

// TreeNodeCache is a cache that maps from token to treeNode. Since the mapping
// is not 1-1 (many Token can point to one TreeNode, but one token leads to one
// TreeNode), we have to do certain
// lookup, but that's better than searching the tree each time.
type TreeNodeCache struct {
	Entries map[TreeID]map[TreeNodeID]*TreeNode
	sync.Mutex
}

// NewTreeNodeCache Returns a new TreeNodeCache
func NewTreeNodeCache() *TreeNodeCache {
	return &TreeNodeCache{
		Entries: make(map[TreeID]map[TreeNodeID]*TreeNode),
	}
}

// Cache a TreeNode that relates to the Tree
// It will also cache the parent and children of the treenode since that's most
// likely what we are going to query.
func (tnc *TreeNodeCache) Cache(tree *Tree, treeNode *TreeNode) {
	tnc.Lock()
	defer tnc.Unlock()
	mm, ok := tnc.Entries[tree.ID]
	if !ok {
		mm = make(map[TreeNodeID]*TreeNode)
	}
	// add treenode
	mm[treeNode.ID] = treeNode
	// add parent if not root
	if treeNode.Parent != nil {
		mm[treeNode.Parent.ID] = treeNode.Parent
	}
	// add children
	for _, c := range treeNode.Children {
		mm[c.ID] = c
	}
	// add cache
	tnc.Entries[tree.ID] = mm
}

// GetFromToken returns the TreeNode that the token is pointing at, or
// nil if there is none for this token.
func (tnc *TreeNodeCache) GetFromToken(tok *Token) *TreeNode {
	tnc.Lock()
	defer tnc.Unlock()
	if tok == nil {
		return nil
	}
	mm, ok := tnc.Entries[tok.TreeID]
	if !ok {
		// no tree cached for this token :...
		return nil
	}
	tn, ok := mm[tok.TreeNodeID]
	if !ok {
		// no treeNode cached for this token...
		// XXX Should we search the tree ? Then we need to keep reference to the
		// tree ...
		return nil
	}
	return tn
}

// defaultProtoIO implements the ProtocoIO interface but using the "regular/old"
// wire format protocol,i.e. it wraps a message into a ProtocolMessage
type defaultProtoIO struct{}

// Wrap implements the MessageProxy interface for the Overlay.
func (d *defaultProtoIO) Wrap(msg interface{}, info *OverlayMessage) (interface{}, error) {
	if msg != nil {
		buff, err := network.MarshalRegisteredType(msg)
		if err != nil {
			return nil, err
		}
		typ := network.TypeFromData(msg)
		protoMsg := &ProtocolMsg{
			From:     info.TreeNodeInfo.From,
			To:       info.TreeNodeInfo.To,
			MsgSlice: buff,
			MsgType:  typ,
		}
		return protoMsg, nil
	}
	var returnMsg interface{}
	switch true {
	case info.RequestTree != nil:
		returnMsg = info.RequestTree
	case info.RequestRoster != nil:
		returnMsg = info.RequestRoster
	case info.TreeMarshal != nil:
		returnMsg = info.TreeMarshal
	case info.Roster != nil:
		returnMsg = info.Roster
	default:
		panic("overlay: default wrapper has nothing to wrap")
	}
	return returnMsg, nil
}

// Unwrap implements the MessageProxy interface for the Overlay.
func (d *defaultProtoIO) Unwrap(msg interface{}) (interface{}, *OverlayMessage, error) {
	var returnMsg interface{}
	var returnOverlay = new(OverlayMessage)
	var err error

	switch inner := msg.(type) {
	case ProtocolMsg:
		onetMsg := inner
		var err error
		_, protoMsg, err := network.UnmarshalRegistered(onetMsg.MsgSlice)
		if err != nil {
			return nil, nil, err
		}
		// Put the msg into ProtocolMsg
		returnOverlay.TreeNodeInfo = &TreeNodeInfo{
			To:   onetMsg.To,
			From: onetMsg.From,
		}
		returnMsg = protoMsg
	case RequestTree:
		returnOverlay.RequestTree = &inner
	case RequestRoster:
		returnOverlay.RequestRoster = &inner
	case TreeMarshal:
		returnOverlay.TreeMarshal = &inner
	case Roster:
		returnOverlay.Roster = &inner
	default:
		err = errors.New("default protoIO: unwraping an unknown message type")
	}
	return returnMsg, returnOverlay, err
}

// Unwrap implements the MessageProxy interface for the Overlay.
func (d *defaultProtoIO) PacketType() network.PacketTypeID {
	return network.PacketTypeID([16]byte{})
}

// Name implements the MessageProxy interface. It returns the value "default".
func (d *defaultProtoIO) Name() string {
	return "default"
}
