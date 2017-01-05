package onet

import (
	"errors"
	"strconv"
	"time"

	"os"

	"github.com/dedis/crypto/abstract"
	"github.com/dedis/crypto/config"
	"github.com/dedis/onet/log"
	"github.com/dedis/onet/network"
	"github.com/satori/go.uuid"
)

// LocalTest represents all that is needed for a local test-run
type LocalTest struct {
	// A map of ServerIdentity.Id to Conode
	Conodes map[network.ServerIdentityID]*Conode
	// A map of ServerIdentity.Id to Overlays
	Overlays map[network.ServerIdentityID]*Overlay
	// A map of ServerIdentity.Id to Services
	Services map[network.ServerIdentityID]map[ServiceID]Service
	// A map of Roster.Id to Rosters
	Rosters map[RosterID]*Roster
	// A map of Tree.Id to Trees
	Trees map[TreeID]*Tree
	// All single nodes
	Nodes []*TreeNodeInstance
	// are we running tcp or local layer
	mode string
	// the context for the local connections
	// it enables to have multiple local test running simultaneously
	ctx *network.LocalManager
}

const (
	// TCP represents the TCP mode of networking for this local test
	TCP = "tcp"
	// Local represents the Local mode of networking for this local test
	Local = "local"
)

// NewLocalTest creates a new Local handler that can be used to test protocols
// locally
func NewLocalTest() *LocalTest {
	if s, err := os.Stat("config"); err == nil && s.IsDir() {
		log.Lvl4("Removing config-dir")
		os.RemoveAll("config")
	}
	return &LocalTest{
		Conodes:  make(map[network.ServerIdentityID]*Conode),
		Overlays: make(map[network.ServerIdentityID]*Overlay),
		Services: make(map[network.ServerIdentityID]map[ServiceID]Service),
		Rosters:  make(map[RosterID]*Roster),
		Trees:    make(map[TreeID]*Tree),
		Nodes:    make([]*TreeNodeInstance, 0, 1),
		mode:     Local,
		ctx:      network.NewLocalManager(),
	}
}

// NewTCPTest returns a LocalTest but using a TCPRouter as the underlying
// communication layer.
func NewTCPTest() *LocalTest {
	t := NewLocalTest()
	t.mode = TCP
	return t
}

// StartProtocol takes a name and a tree and will create a
// new Node with the protocol 'name' running from the tree-root
func (l *LocalTest) StartProtocol(name string, t *Tree) (ProtocolInstance, error) {
	rootServerIdentityID := t.Root.ServerIdentity.ID
	for _, h := range l.Conodes {
		if h.ServerIdentity.ID.Equal(rootServerIdentityID) {
			// XXX do we really need multiples overlays ? Can't we just use the
			// Node, since it is already dispatched as like a TreeNode ?
			return l.Overlays[h.ServerIdentity.ID].StartProtocol(name, t, NilServiceID)
		}
	}
	return nil, errors.New("Didn't find conode for tree-root")
}

// CreateProtocol takes a name and a tree and will create a
// new Node with the protocol 'name' without running it
func (l *LocalTest) CreateProtocol(name string, t *Tree) (ProtocolInstance, error) {
	rootServerIdentityID := t.Root.ServerIdentity.ID
	for _, h := range l.Conodes {
		if h.ServerIdentity.ID.Equal(rootServerIdentityID) {
			// XXX do we really need multiples overlays ? Can't we just use the
			// Node, since it is already dispatched as like a TreeNode ?
			return l.Overlays[h.ServerIdentity.ID].CreateProtocol(name, t, NilServiceID)
		}
	}
	return nil, errors.New("Didn't find conode for tree-root")
}

// GenConodes returns n Hosts with a localRouter
func (l *LocalTest) GenConodes(n int) []*Conode {
	conodes := l.genLocalHosts(n)
	for _, conode := range conodes {
		l.Conodes[conode.ServerIdentity.ID] = conode
		l.Overlays[conode.ServerIdentity.ID] = conode.overlay
		l.Services[conode.ServerIdentity.ID] = conode.serviceManager.services
	}
	return conodes

}

// GenTree will create a tree of n conodes with a localRouter, and returns the
// list of conodes and the associated roster / tree.
func (l *LocalTest) GenTree(n int, register bool) ([]*Conode, *Roster, *Tree) {
	conodes := l.GenConodes(n)

	list := l.GenRosterFromHost(conodes...)
	tree := list.GenerateBinaryTree()
	l.Trees[tree.ID] = tree
	if register {
		conodes[0].overlay.RegisterRoster(list)
		conodes[0].overlay.RegisterTree(tree)
	}
	return conodes, list, tree

}

// GenBigTree will create a tree of n conodes.
// If register is true, the Roster and Tree will be registered with the overlay.
// 'nbrConodes' is how many conodes are created
// 'nbrTreeNodes' is how many TreeNodes are created
// nbrConodes can be smaller than nbrTreeNodes, in which case a given conode will
// be used more than once in the tree.
func (l *LocalTest) GenBigTree(nbrTreeNodes, nbrConodes, bf int, register bool) ([]*Conode, *Roster, *Tree) {
	conodes := l.GenConodes(nbrConodes)

	list := l.GenRosterFromHost(conodes...)
	tree := list.GenerateBigNaryTree(bf, nbrTreeNodes)
	l.Trees[tree.ID] = tree
	if register {
		conodes[0].overlay.RegisterRoster(list)
		conodes[0].overlay.RegisterTree(tree)
	}
	return conodes, list, tree
}

// GenRosterFromHost takes a number of conodes as arguments and creates
// an Roster.
func (l *LocalTest) GenRosterFromHost(conodes ...*Conode) *Roster {
	var entities []*network.ServerIdentity
	for i := range conodes {
		entities = append(entities, conodes[i].ServerIdentity)
	}
	list := NewRoster(entities)
	l.Rosters[list.ID] = list
	return list
}

// CloseAll takes a list of conodes that will be closed
func (l *LocalTest) CloseAll() {
	for _, conode := range l.Conodes {
		log.Lvl3("Closing conode", conode.ServerIdentity.Address)
		err := conode.Close()
		if err != nil {
			log.Error("Closing conode", conode.ServerIdentity.Address,
				"gives error", err)
		}

		for conode.Listening() {
			log.Lvl1("Sleeping while waiting to close...")
			time.Sleep(10 * time.Millisecond)
		}
		delete(l.Conodes, conode.ServerIdentity.ID)
	}
	for _, node := range l.Nodes {
		log.Lvl3("Closing node", node)
		node.Close()
	}
	l.Nodes = make([]*TreeNodeInstance, 0)
	// Give the nodes some time to correctly close down
	//time.Sleep(time.Millisecond * 500)
}

// GetTree returns the tree of the given TreeNode
func (l *LocalTest) GetTree(tn *TreeNode) *Tree {
	var tree *Tree
	for _, t := range l.Trees {
		if tn.IsInTree(t) {
			tree = t
			break
		}
	}
	return tree
}

// NewTreeNodeInstance creates a new node on a TreeNode
func (l *LocalTest) NewTreeNodeInstance(tn *TreeNode, protName string) (*TreeNodeInstance, error) {
	o := l.Overlays[tn.ServerIdentity.ID]
	if o == nil {
		return nil, errors.New("Didn't find corresponding overlay")
	}
	tree := l.GetTree(tn)
	if tree == nil {
		return nil, errors.New("Didn't find tree corresponding to TreeNode")
	}
	protID := ProtocolNameToID(protName)
	if !l.Conodes[tn.ServerIdentity.ID].protocols.ProtocolExists(protID) {
		return nil, errors.New("Didn't find protocol: " + protName)
	}
	tok := &Token{
		ProtoID:    protID,
		RosterID:   tree.Roster.ID,
		TreeID:     tree.ID,
		TreeNodeID: tn.ID,
		RoundID:    RoundID(uuid.NewV4()),
	}
	io := o.protoIO.getByName(protName)
	node := newTreeNodeInstance(o, tok, tn, io)
	l.Nodes = append(l.Nodes, node)
	return node, nil
}

// GetNodes returns all Nodes that belong to a treeNode
func (l *LocalTest) GetNodes(tn *TreeNode) []*TreeNodeInstance {
	var nodes []*TreeNodeInstance
	for _, n := range l.Overlays[tn.ServerIdentity.ID].instances {
		nodes = append(nodes, n)
	}
	return nodes
}

// SendTreeNode injects a message directly in the Overlay-layer, bypassing
// Host and Network
func (l *LocalTest) SendTreeNode(proto string, from, to *TreeNodeInstance, msg network.Body) error {
	if from.Tree().ID != to.Tree().ID {
		return errors.New("Can't send from one tree to another")
	}
	onetMsg := &ProtocolMsg{
		Msg:     msg,
		MsgType: network.TypeToPacketTypeID(msg),
		From:    from.token,
		To:      to.token,
	}
	io := l.Overlays[to.ServerIdentity().ID].protoIO.getByName(proto)
	return to.overlay.TransmitMsg(onetMsg, io)
}

// AddPendingTreeMarshal takes a treeMarshal and adds it to the list of the
// known trees, also triggering dispatching of onet-messages waiting for that
// tree
func (l *LocalTest) AddPendingTreeMarshal(c *Conode, tm *TreeMarshal) {
	c.overlay.addPendingTreeMarshal(tm)
}

// CheckPendingTreeMarshal looks whether there are any treeMarshals to be
// called
func (l *LocalTest) CheckPendingTreeMarshal(c *Conode, el *Roster) {
	c.overlay.checkPendingTreeMarshal(el)
}

// GetPrivate returns the private key of a conode
func (l *LocalTest) GetPrivate(c *Conode) abstract.Scalar {
	return c.private
}

// GetServices returns a slice of all services asked for.
// The sid is the id of the service that will be collected.
func (l *LocalTest) GetServices(conodes []*Conode, sid ServiceID) []Service {
	services := make([]Service, len(conodes))
	for i, h := range conodes {
		services[i] = l.Services[h.ServerIdentity.ID][sid]
	}
	return services
}

// MakeHELS creates nbr conodes, and will return the associated roster. It also
// returns the Service object of the first conodes in the list having sid as a
// ServiceID.
func (l *LocalTest) MakeHELS(nbr int, sid ServiceID) ([]*Conode, *Roster, Service) {
	conodes := l.GenConodes(nbr)
	el := l.GenRosterFromHost(conodes...)
	return conodes, el, l.Services[conodes[0].ServerIdentity.ID][sid]
}

// NewPrivIdentity returns a secret + ServerIdentity. The SI will have
// "localconode:+port as first address.
func NewPrivIdentity(port int) (abstract.Scalar, *network.ServerIdentity) {
	address := network.NewLocalAddress("127.0.0.1:" + strconv.Itoa(port))
	priv, pub := PrivPub()
	id := network.NewServerIdentity(pub, address)
	return priv, id
}

// NewTCPConode creates a new conode with a tcpRouter with "localconode:"+port as an
// address.
func NewTCPConode(port int) *Conode {
	priv, id := NewPrivIdentity(port)
	addr := network.NewTCPAddress(id.Address.NetworkAddress())
	tcpHost, err := network.NewTCPHost(addr)
	if err != nil {
		panic(err)
	}
	id.Address = tcpHost.Address()
	router := network.NewRouter(id, tcpHost)
	h := NewConode(router, priv)
	go h.Start()
	for !h.Listening() {
		time.Sleep(10 * time.Millisecond)
	}
	return h
}

// NewLocalConode returns a new conode using a LocalRouter (channels) to communicate.
// At the return of this function, the router is already Run()ing in a go
// routine.
func NewLocalConode(port int) *Conode {
	priv, id := NewPrivIdentity(port)
	localRouter, err := network.NewLocalRouter(id)
	if err != nil {
		panic(err)
	}
	h := NewConode(localRouter, priv)
	go h.Start()
	for !h.Listening() {
		time.Sleep(10 * time.Millisecond)
	}
	return h
}

// NewClient returns *Client for which the types depend on the mode of the
// LocalContext.
func (l *LocalTest) NewClient(serviceName string) *Client {
	switch l.mode {
	case TCP:
		return NewClient(serviceName)
	default:
		log.Fatal("Can't make local client")
		return nil
	}
}

// genLocalHosts returns n conodes created with a localRouter
func (l *LocalTest) genLocalHosts(n int) []*Conode {
	conodes := make([]*Conode, n)
	for i := 0; i < n; i++ {
		port := 2000 + i*10
		conodes[i] = l.NewConode(port)
	}
	return conodes
}

// NewConode returns a new conode which type is determined by the local mode:
// TCP or Local. If it's TCP, then an available port is used, otherwise, the
// port given in argument is used.
func (l *LocalTest) NewConode(port int) *Conode {
	var conode *Conode
	switch l.mode {
	case TCP:
		conode = l.NewTCPConode()
	default:
		conode = l.NewLocalConode(port)
	}
	return conode
}

// NewTCPConode returns a new TCP Conode attached to this LocalTest.
func (l *LocalTest) NewTCPConode() *Conode {
	conode := NewTCPConode(0)
	l.Conodes[conode.ServerIdentity.ID] = conode
	l.Overlays[conode.ServerIdentity.ID] = conode.overlay
	l.Services[conode.ServerIdentity.ID] = conode.serviceManager.services

	return conode
}

// NewLocalConode returns a fresh Host using local connections within the context
// of this LocalTest
func (l *LocalTest) NewLocalConode(port int) *Conode {
	priv, id := NewPrivIdentity(port)
	localRouter, err := network.NewLocalRouterWithManager(l.ctx, id)
	if err != nil {
		panic(err)
	}
	conode := NewConode(localRouter, priv)
	go conode.Start()
	for !conode.Listening() {
		time.Sleep(10 * time.Millisecond)
	}
	l.Conodes[conode.ServerIdentity.ID] = conode
	l.Overlays[conode.ServerIdentity.ID] = conode.overlay
	l.Services[conode.ServerIdentity.ID] = conode.serviceManager.services

	return conode

}

// PrivPub creates a private/public key pair.
func PrivPub() (abstract.Scalar, abstract.Point) {
	keypair := config.NewKeyPair(network.Suite)
	return keypair.Secret, keypair.Public
}
