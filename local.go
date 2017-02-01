package onet

import (
	"errors"
	"strconv"
	"time"

	"os"

	"fmt"
	"net"

	"github.com/dedis/onet/log"
	"github.com/dedis/onet/network"
	"github.com/satori/go.uuid"
	"gopkg.in/dedis/crypto.v0/abstract"
	"gopkg.in/dedis/crypto.v0/config"
)

// LocalTest represents all that is needed for a local test-run
type LocalTest struct {
	// A map of ServerIdentity.Id to Servers
	Servers map[network.ServerIdentityID]*Server
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
	setContextDataPath("")
	return &LocalTest{
		Servers:  make(map[network.ServerIdentityID]*Server),
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
	setContextDataPath("")
	return t
}

// StartProtocol takes a name and a tree and will create a
// new Node with the protocol 'name' running from the tree-root
func (l *LocalTest) StartProtocol(name string, t *Tree) (ProtocolInstance, error) {
	rootServerIdentityID := t.Root.ServerIdentity.ID
	for _, h := range l.Servers {
		if h.ServerIdentity.ID.Equal(rootServerIdentityID) {
			// XXX do we really need multiples overlays ? Can't we just use the
			// Node, since it is already dispatched as like a TreeNode ?
			return l.Overlays[h.ServerIdentity.ID].StartProtocol(name, t, NilServiceID)
		}
	}
	return nil, errors.New("Didn't find server for tree-root")
}

// CreateProtocol takes a name and a tree and will create a
// new Node with the protocol 'name' without running it
func (l *LocalTest) CreateProtocol(name string, t *Tree) (ProtocolInstance, error) {
	rootServerIdentityID := t.Root.ServerIdentity.ID
	for _, h := range l.Servers {
		if h.ServerIdentity.ID.Equal(rootServerIdentityID) {
			// XXX do we really need multiples overlays ? Can't we just use the
			// Node, since it is already dispatched as like a TreeNode ?
			return l.Overlays[h.ServerIdentity.ID].CreateProtocol(name, t, NilServiceID)
		}
	}
	return nil, errors.New("Didn't find server for tree-root")
}

// GenServers returns n Servers with a localRouter
func (l *LocalTest) GenServers(n int) []*Server {
	servers := l.genLocalHosts(n)
	for _, server := range servers {
		l.Servers[server.ServerIdentity.ID] = server
		l.Overlays[server.ServerIdentity.ID] = server.overlay
		l.Services[server.ServerIdentity.ID] = server.serviceManager.services
	}
	return servers

}

// GenTree will create a tree of n servers with a localRouter, and returns the
// list of servers and the associated roster / tree.
func (l *LocalTest) GenTree(n int, register bool) ([]*Server, *Roster, *Tree) {
	servers := l.GenServers(n)

	list := l.GenRosterFromHost(servers...)
	tree := list.GenerateBinaryTree()
	l.Trees[tree.ID] = tree
	if register {
		servers[0].overlay.RegisterRoster(list)
		servers[0].overlay.RegisterTree(tree)
	}
	return servers, list, tree

}

// GenBigTree will create a tree of n servers.
// If register is true, the Roster and Tree will be registered with the overlay.
// 'nbrServers' is how many servers are created
// 'nbrTreeNodes' is how many TreeNodes are created
// nbrServers can be smaller than nbrTreeNodes, in which case a given server will
// be used more than once in the tree.
func (l *LocalTest) GenBigTree(nbrTreeNodes, nbrServers, bf int, register bool) ([]*Server, *Roster, *Tree) {
	servers := l.GenServers(nbrServers)

	list := l.GenRosterFromHost(servers...)
	tree := list.GenerateBigNaryTree(bf, nbrTreeNodes)
	l.Trees[tree.ID] = tree
	if register {
		servers[0].overlay.RegisterRoster(list)
		servers[0].overlay.RegisterTree(tree)
	}
	return servers, list, tree
}

// GenRosterFromHost takes a number of servers as arguments and creates
// an Roster.
func (l *LocalTest) GenRosterFromHost(servers ...*Server) *Roster {
	var entities []*network.ServerIdentity
	for i := range servers {
		entities = append(entities, servers[i].ServerIdentity)
	}
	list := NewRoster(entities)
	l.Rosters[list.ID] = list
	return list
}

// CloseAll takes a list of servers that will be closed
func (l *LocalTest) CloseAll() {
	for _, server := range l.Servers {
		log.Lvl3("Closing server", server.ServerIdentity.Address)
		err := server.Close()
		if err != nil {
			log.Error("Closing server", server.ServerIdentity.Address,
				"gives error", err)
		}

		for server.Listening() {
			log.Lvl1("Sleeping while waiting to close...")
			time.Sleep(10 * time.Millisecond)
		}
		delete(l.Servers, server.ServerIdentity.ID)
	}
	for _, node := range l.Nodes {
		log.Lvl3("Closing node", node)
		node.closeDispatch()
	}
	l.Nodes = make([]*TreeNodeInstance, 0)
	// Give the nodes some time to correctly close down
	//time.Sleep(time.Millisecond * 500)
}

// getTree returns the tree of the given TreeNode
func (l *LocalTest) getTree(tn *TreeNode) *Tree {
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
	tree := l.getTree(tn)
	if tree == nil {
		return nil, errors.New("Didn't find tree corresponding to TreeNode")
	}
	protID := ProtocolNameToID(protName)
	if !l.Servers[tn.ServerIdentity.ID].protocols.ProtocolExists(protID) {
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

// getNodes returns all Nodes that belong to a treeNode
func (l *LocalTest) getNodes(tn *TreeNode) []*TreeNodeInstance {
	var nodes []*TreeNodeInstance
	for _, n := range l.Overlays[tn.ServerIdentity.ID].instances {
		nodes = append(nodes, n)
	}
	return nodes
}

// sendTreeNode injects a message directly in the Overlay-layer, bypassing
// Host and Network
func (l *LocalTest) sendTreeNode(proto string, from, to *TreeNodeInstance, msg network.Message) error {
	if from.Tree().ID != to.Tree().ID {
		return errors.New("Can't send from one tree to another")
	}
	onetMsg := &ProtocolMsg{
		Msg:     msg,
		MsgType: network.MessageType(msg),
		From:    from.token,
		To:      to.token,
	}
	io := l.Overlays[to.ServerIdentity().ID].protoIO.getByName(proto)
	return to.overlay.TransmitMsg(onetMsg, io)
}

// addPendingTreeMarshal takes a treeMarshal and adds it to the list of the
// known trees, also triggering dispatching of onet-messages waiting for that
// tree
func (l *LocalTest) addPendingTreeMarshal(c *Server, tm *TreeMarshal) {
	c.overlay.addPendingTreeMarshal(tm)
}

// checkPendingTreeMarshal looks whether there are any treeMarshals to be
// called
func (l *LocalTest) checkPendingTreeMarshal(c *Server, el *Roster) {
	c.overlay.checkPendingTreeMarshal(el)
}

// GetPrivate returns the private key of a server
func (l *LocalTest) GetPrivate(c *Server) abstract.Scalar {
	return c.private
}

// GetServices returns a slice of all services asked for.
// The sid is the id of the service that will be collected.
func (l *LocalTest) GetServices(servers []*Server, sid ServiceID) []Service {
	services := make([]Service, len(servers))
	for i, h := range servers {
		services[i] = l.Services[h.ServerIdentity.ID][sid]
	}
	return services
}

// MakeHELS creates nbr servers, and will return the associated roster. It also
// returns the Service object of the first servers in the list having sid as a
// ServiceID.
func (l *LocalTest) MakeHELS(nbr int, sid ServiceID) ([]*Server, *Roster, Service) {
	servers := l.GenServers(nbr)
	el := l.GenRosterFromHost(servers...)
	return servers, el, l.Services[servers[0].ServerIdentity.ID][sid]
}

// NewPrivIdentity returns a secret + ServerIdentity. The SI will have
// "localserver:+port as first address.
func NewPrivIdentity(port int) (abstract.Scalar, *network.ServerIdentity) {
	address := network.NewLocalAddress("127.0.0.1:" + strconv.Itoa(port))
	priv, pub := PrivPub()
	id := network.NewServerIdentity(pub, address)
	return priv, id
}

// NewTCPServer creates a new server with a tcpRouter with "localserver:"+port as an
// address.
func NewTCPServer(port int) *Server {
	priv, id := NewPrivIdentity(port)
	addr := network.NewTCPAddress(id.Address.NetworkAddress())
	var tcpHost *network.TCPHost
	// For the websocket we need a port at the address one higher than the
	// TCPHost. Let TCPHost chose a port, then check if the port+1 is also
	// available. Else redo the search.
	for {
		var err error
		tcpHost, err = network.NewTCPHost(addr)
		if err != nil {
			panic(err)
		}
		id.Address = tcpHost.Address()
		if port != 0 {
			break
		}
		port, err := strconv.Atoi(id.Address.Port())
		if err != nil {
			panic(err)
		}
		addr := fmt.Sprintf("%s:%d", id.Address.Host(), port+1)
		if l, err := net.Listen("tcp", addr); err == nil {
			l.Close()
			break
		}
		log.Lvl2("Found closed port:", addr)
	}
	router := network.NewRouter(id, tcpHost)
	h := NewServer(router, priv)
	go h.Start()
	for !h.Listening() {
		time.Sleep(10 * time.Millisecond)
	}
	return h
}

// NewLocalServer returns a new server using a LocalRouter (channels) to communicate.
// At the return of this function, the router is already Run()ing in a go
// routine.
func NewLocalServer(port int) *Server {
	priv, id := NewPrivIdentity(port)
	localRouter, err := network.NewLocalRouter(id)
	if err != nil {
		panic(err)
	}
	h := NewServer(localRouter, priv)
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

// genLocalHosts returns n servers created with a localRouter
func (l *LocalTest) genLocalHosts(n int) []*Server {
	servers := make([]*Server, n)
	for i := 0; i < n; i++ {
		port := 2000 + i*10
		servers[i] = l.NewServer(port)
	}
	return servers
}

// NewServer returns a new server which type is determined by the local mode:
// TCP or Local. If it's TCP, then an available port is used, otherwise, the
// port given in argument is used.
func (l *LocalTest) NewServer(port int) *Server {
	var server *Server
	switch l.mode {
	case TCP:
		server = l.NewTCPServer()
	default:
		server = l.NewLocalServer(port)
	}
	return server
}

// NewTCPServer returns a new TCP Server attached to this LocalTest.
func (l *LocalTest) NewTCPServer() *Server {
	server := NewTCPServer(0)
	l.Servers[server.ServerIdentity.ID] = server
	l.Overlays[server.ServerIdentity.ID] = server.overlay
	l.Services[server.ServerIdentity.ID] = server.serviceManager.services

	return server
}

// NewLocalServer returns a fresh Host using local connections within the context
// of this LocalTest
func (l *LocalTest) NewLocalServer(port int) *Server {
	priv, id := NewPrivIdentity(port)
	localRouter, err := network.NewLocalRouterWithManager(l.ctx, id)
	if err != nil {
		panic(err)
	}
	server := NewServer(localRouter, priv)
	go server.Start()
	for !server.Listening() {
		time.Sleep(10 * time.Millisecond)
	}
	l.Servers[server.ServerIdentity.ID] = server
	l.Overlays[server.ServerIdentity.ID] = server.overlay
	l.Services[server.ServerIdentity.ID] = server.serviceManager.services

	return server

}

// PrivPub creates a private/public key pair.
func PrivPub() (abstract.Scalar, abstract.Point) {
	keypair := config.NewKeyPair(network.Suite)
	return keypair.Secret, keypair.Public
}
