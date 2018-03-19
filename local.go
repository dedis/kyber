package onet

import (
	"errors"
	"io/ioutil"
	"net"
	"os"
	"strconv"
	"testing"
	"time"

	"gopkg.in/dedis/kyber.v2"
	"gopkg.in/dedis/kyber.v2/util/key"
	"gopkg.in/dedis/onet.v2/log"
	"gopkg.in/dedis/onet.v2/network"
)

// LocalTest represents all that is needed for a local test-run
type LocalTest struct {
	// A map of ServerIdentity.Id to Servers
	Servers map[network.ServerIdentityID]*Server
	// A map of ServerIdentity.Id to Overlays
	Overlays map[network.ServerIdentityID]*Overlay
	// A map of ServerIdentity.Id to Services
	Services map[network.ServerIdentityID]map[ServiceID]Service
	// A map of Tree.Id to Trees
	Trees map[TreeID]*Tree
	// All single nodes
	Nodes []*TreeNodeInstance
	// are we running tcp or local layer
	mode string
	// the context for the local connections
	// it enables to have multiple local test running simultaneously
	ctx   *network.LocalManager
	Suite network.Suite
	path  string
	// Once closed is set, do not allow further operations on it,
	// since now the temp directory is gone.
	closed bool
	T      *testing.T
}

const (
	// TCP represents the TCP mode of networking for this local test
	TCP = "tcp"
	// Local represents the Local mode of networking for this local test
	Local = "local"
)

// NewLocalTest creates a new Local handler that can be used to test protocols
// locally
func NewLocalTest(s network.Suite) *LocalTest {
	dir, err := ioutil.TempDir("", "onet")
	if err != nil {
		log.Fatal("could not create temp directory: ", err)
	}

	return &LocalTest{
		Servers:  make(map[network.ServerIdentityID]*Server),
		Overlays: make(map[network.ServerIdentityID]*Overlay),
		Services: make(map[network.ServerIdentityID]map[ServiceID]Service),
		Trees:    make(map[TreeID]*Tree),
		Nodes:    make([]*TreeNodeInstance, 0, 1),
		mode:     Local,
		ctx:      network.NewLocalManager(),
		Suite:    s,
		path:     dir,
	}
}

// NewTCPTest returns a LocalTest but using a TCPRouter as the underlying
// communication layer.
func NewTCPTest(s network.Suite) *LocalTest {
	t := NewLocalTest(s)
	t.mode = TCP
	return t
}

// StartProtocol takes a name and a tree and will create a
// new Node with the protocol 'name' running from the tree-root
func (l *LocalTest) StartProtocol(name string, t *Tree) (ProtocolInstance, error) {
	l.panicClosed()
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
	l.panicClosed()
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
	l.panicClosed()
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
	l.panicClosed()
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
	l.panicClosed()
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
	l.panicClosed()
	var entities []*network.ServerIdentity
	for i := range servers {
		entities = append(entities, servers[i].ServerIdentity)
	}
	return NewRoster(entities)
}

func (l *LocalTest) panicClosed() {
	if l.closed {
		panic("attempt to use LocalTest after CloseAll")
	}
}

// CloseAll closes all the servers.
func (l *LocalTest) CloseAll() {
	log.Lvl3("Stopping all")
	// If the debug-level is 0, we copy all errors to a buffer that
	// will be discarded at the end.
	if log.DebugVisible() == 0 {
		log.OutputToBuf()
	}

	if l.T != nil {
		ct := 0
		for _, o := range l.Overlays {
			for _, pi := range o.protocolInstances {
				l.T.Logf("Lingering protocol instance: %T", pi)
				ct++
			}
		}
		if ct > 0 {
			l.T.Fatal("Protocols lingering.")
		}
	}

	l.ctx.Stop()
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
	os.RemoveAll(l.path)
	l.closed = true
	if log.DebugVisible() == 0 {
		log.OutputToOs()
	}
}

// getTree returns the tree of the given TreeNode
func (l *LocalTest) getTree(tn *TreeNode) *Tree {
	l.panicClosed()
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
	l.panicClosed()
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
		TreeID:     tree.ID,
		TreeNodeID: tn.ID,
	}
	io := o.protoIO.getByName(protName)
	node := newTreeNodeInstance(o, tok, tn, io)
	l.Nodes = append(l.Nodes, node)
	return node, nil
}

// getNodes returns all Nodes that belong to a treeNode
func (l *LocalTest) getNodes(tn *TreeNode) []*TreeNodeInstance {
	l.panicClosed()
	var nodes []*TreeNodeInstance
	for _, n := range l.Overlays[tn.ServerIdentity.ID].instances {
		nodes = append(nodes, n)
	}
	return nodes
}

// sendTreeNode injects a message directly in the Overlay-layer, bypassing
// Host and Network
func (l *LocalTest) sendTreeNode(proto string, from, to *TreeNodeInstance, msg network.Message) error {
	l.panicClosed()
	if !from.Tree().ID.Equal(to.Tree().ID) {
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
	l.panicClosed()
	c.overlay.addPendingTreeMarshal(tm)
}

// checkPendingTreeMarshal looks whether there are any treeMarshals to be
// called
func (l *LocalTest) checkPendingTreeMarshal(c *Server, el *Roster) {
	l.panicClosed()
	c.overlay.checkPendingTreeMarshal(el)
}

// GetPrivate returns the private key of a server
func (l *LocalTest) GetPrivate(c *Server) kyber.Scalar {
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

// MakeSRS creates and returns nbr Servers, the associated Roster and the
// Service object of the first server in the list having sid as a ServiceID.
func (l *LocalTest) MakeSRS(s network.Suite, nbr int, sid ServiceID) ([]*Server, *Roster, Service) {
	l.panicClosed()
	servers := l.GenServers(nbr)
	el := l.GenRosterFromHost(servers...)
	return servers, el, l.Services[servers[0].ServerIdentity.ID][sid]
}

// NewPrivIdentity returns a secret + ServerIdentity. The SI will have
// "localserver:+port as first address.
func NewPrivIdentity(suite network.Suite, port int) (kyber.Scalar, *network.ServerIdentity) {
	address := network.NewLocalAddress("127.0.0.1:" + strconv.Itoa(port))
	kp := key.NewKeyPair(suite)
	id := network.NewServerIdentity(kp.Public, address)
	return kp.Private, id
}

// NewTCPServer creates a new server with a tcpRouter with "localhost:"+port as an
// address.
func newTCPServer(s network.Suite, port int, path string) *Server {
	priv, id := NewPrivIdentity(s, port)
	addr := network.NewAddress(network.PlainTCP, id.Address.NetworkAddress())
	id2 := network.NewServerIdentity(id.Public, addr)
	var tcpHost *network.TCPHost
	// For the websocket we need a port at the address one higher than the
	// TCPHost. Let TCPHost chose a port, then check if the port+1 is also
	// available. Else redo the search.
	for {
		var err error
		tcpHost, err = network.NewTCPHost(id2, s)
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
		addr := net.JoinHostPort(id.Address.Host(), strconv.Itoa(port+1))
		if l, err := net.Listen("tcp", addr); err == nil {
			l.Close()
			break
		}
		log.Lvl2("Found closed port:", addr)
	}
	id.Address = network.NewAddress(id.Address.ConnType(), "127.0.0.1:"+id.Address.Port())
	router := network.NewRouter(id, tcpHost)
	router.UnauthOk = true
	h := newServer(s, path, router, priv)
	go h.Start()
	for !h.Listening() {
		time.Sleep(10 * time.Millisecond)
	}
	return h
}

// NewLocalServer returns a new server using a LocalRouter (channels) to communicate.
// At the return of this function, the router is already Run()ing in a go
// routine.
func NewLocalServer(s network.Suite, port int) *Server {
	dir, err := ioutil.TempDir("", "example")
	if err != nil {
		log.Fatal(err)
	}

	priv, id := NewPrivIdentity(s, port)
	localRouter, err := network.NewLocalRouter(id, s)
	if err != nil {
		panic(err)
	}
	h := newServer(s, dir, localRouter, priv)
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
		return NewClient(l.Suite, serviceName)
	default:
		log.Fatal("Can't make local client")
		return nil
	}
}

// genLocalHosts returns n servers created with a localRouter
func (l *LocalTest) genLocalHosts(n int) []*Server {
	l.panicClosed()
	servers := make([]*Server, n)
	for i := 0; i < n; i++ {
		port := 2000 + i*10
		servers[i] = l.NewServer(l.Suite, port)
	}
	return servers
}

// NewServer returns a new server which type is determined by the local mode:
// TCP or Local. If it's TCP, then an available port is used, otherwise, the
// port given in argument is used.
func (l *LocalTest) NewServer(s network.Suite, port int) *Server {
	l.panicClosed()
	var server *Server
	switch l.mode {
	case TCP:
		server = l.newTCPServer(s)
	default:
		server = l.NewLocalServer(s, port)
	}
	return server
}

// NewTCPServer returns a new TCP Server attached to this LocalTest.
func (l *LocalTest) newTCPServer(s network.Suite) *Server {
	l.panicClosed()
	server := newTCPServer(s, 0, l.path)
	l.Servers[server.ServerIdentity.ID] = server
	l.Overlays[server.ServerIdentity.ID] = server.overlay
	l.Services[server.ServerIdentity.ID] = server.serviceManager.services

	return server
}

// NewLocalServer returns a fresh Host using local connections within the context
// of this LocalTest
func (l *LocalTest) NewLocalServer(s network.Suite, port int) *Server {
	l.panicClosed()
	priv, id := NewPrivIdentity(s, port)
	localRouter, err := network.NewLocalRouterWithManager(l.ctx, id, s)
	if err != nil {
		panic(err)
	}
	server := newServer(s, l.path, localRouter, priv)
	go server.Start()
	for !server.Listening() {
		time.Sleep(10 * time.Millisecond)
	}
	l.Servers[server.ServerIdentity.ID] = server
	l.Overlays[server.ServerIdentity.ID] = server.overlay
	l.Services[server.ServerIdentity.ID] = server.serviceManager.services

	return server

}
