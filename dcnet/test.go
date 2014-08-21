package dcnet

import (
	"os"
	"fmt"
	"time"
	"bytes"
	"crypto/cipher"
	"dissent/crypto"
)

type TestNode struct {

	// General parameters
	suite crypto.Suite
	name string

	// Session keypair for this node
	spub crypto.Point
	spri crypto.Secret

	npeers int
	peerkeys []crypto.Point		// each peer's session public key
	peerstreams []cipher.Stream	// shared session master streams

	// Owner keypair for this cell series.
	// Public key is known by and common to all nodes.
	// Private key is held only by owner client.
	opub crypto.Point
	opri crypto.Secret

	Coder CellCoder

	// Stream representing history as seen by this node.
	Histoream cipher.Stream
}

type TestGroup struct {
	Relay *TestNode
	Clients []*TestNode
	Trustees []*TestNode
}

func (n *TestNode) nodeSetup(name string, peerkeys []crypto.Point) {
	n.name = name
	//println("Setup",name)

	// Form Diffie-Hellman master secret shared with each peer,
	// and a pseudorandom master stream derived from each.
	n.npeers = len(peerkeys)
	n.peerkeys = peerkeys
	n.peerstreams = make([]cipher.Stream, n.npeers)
	for j := range(peerkeys) {
		dh := n.suite.Point().Mul(peerkeys[j], n.spri)
		//println(" DH",dh.String())
		n.peerstreams[j] = crypto.PointStream(n.suite, dh)
	}
}

func TestSetup(suite crypto.Suite, factory CellFactory,
		nclients, ntrustees int) *TestGroup {

	// Use a pseudorandom stream from a well-known seed
	// for all our setup randomness,
	// so we can reproduce the same keys etc on each node.
	rand := crypto.HashStream(suite, []byte("DCTest"))

	nodes := make([]*TestNode, nclients+ntrustees)
	base := suite.Point().Base()
	for i := range(nodes) {
		nodes[i] = new(TestNode)
		nodes[i].suite = suite

		// Each client and trustee gets a session keypair
		nodes[i].spri = suite.Secret().Pick(rand)
		nodes[i].spub = suite.Point().Mul(base, nodes[i].spri)
		fmt.Printf("node %d key %s\n", i, nodes[i].spri.String())

		nodes[i].Coder = factory()
	}

	clients := nodes[:nclients]
	trustees := nodes[nclients:]

	relay := new(TestNode)
	relay.name = "Relay"
	relay.Coder = factory()

	// Create tables of the clients' and the trustees' public session keys
	ckeys := make([]crypto.Point, nclients)
	tkeys := make([]crypto.Point, ntrustees)
	for i := range(clients) {
		ckeys[i] = clients[i].spub
	}
	for j := range(trustees) {
		tkeys[j] = trustees[j].spub
	}

	// Pick an "owner" for the (one) transmission series we'll have.
	// For now the owner will be the first client.
	opri := suite.Secret().Pick(rand)
	opub := suite.Point().Mul(base, opri)
	clients[0].opri = opri
	for i := range(nodes) {
		nodes[i].opub = opub	// Everyone knows owner public key
	}

	// Setup the clients and servers to know each others' session keys.
	// XXX this should by something generic across multiple cell types,
	// producing master shared streams that each cell type derives from.
	for i := range(clients) {
		n := clients[i]
		n.nodeSetup(fmt.Sprintf("Client%d",i), tkeys)
		n.Coder = factory()
		n.Coder.ClientSetup(suite, n.peerstreams)
	}
	tinfo := make([][]byte, ntrustees)
	for j := range(trustees) {
		n := trustees[j]
		n.nodeSetup(fmt.Sprintf("Trustee%d",j), ckeys)
		n.Coder = factory()
		tinfo[j] = n.Coder.TrusteeSetup(suite, n.peerstreams)
	}
	relay.Coder.RelaySetup(suite, tinfo)

	// Create a set of fake history streams for the relay and clients
	hist := []byte("xyz")
	relay.Histoream = crypto.HashStream(suite, hist)
	//relay.Histoream = crypto.TraceStream(os.Stdout, relay.Histoream)
	for i := range(clients) {
		clients[i].Histoream = crypto.HashStream(suite, hist)
		//clients[i].Histoream = crypto.TraceStream(os.Stdout,
		//					clients[i].Histoream)
	}

	tg := new(TestGroup)
	tg.Relay = relay
	tg.Clients = clients
	tg.Trustees = trustees
	return tg
}

func TestCellCoder(suite crypto.Suite, factory CellFactory) {

	nclients := 1
	ntrustees := 3

	tg := TestSetup(suite, factory, nclients, ntrustees)
	relay := tg.Relay
	clients := tg.Clients
	trustees := tg.Trustees

	// Get some data to transmit
	println("Simulating DC-nets")
	payloadlen := 1200
	inb := make([]byte, payloadlen)
	//inf,_ := os.Open("../LOW_LATENCY_DESIGN")
	inf,_ := os.Open("/usr/bin/afconvert")
	beg := time.Now()
	ncells := 0
	nbytes := 0
	cslice := make([][]byte, nclients)
	tslice := make([][]byte, ntrustees)
	for {
		n,_ := inf.Read(inb)
		if n <= 0 {
			break
		}
		payloadlen = n

		// Client processing
		// first client (owner) gets the payload data
		p := make([]byte, payloadlen)
		copy(p, inb)
		for i := range(clients) {
p = nil
			cslice[i] = clients[i].Coder.ClientEncode(p, payloadlen,
						clients[i].Histoream)
			p = nil		// for remaining clients
		}

		// Trustee processing
		for j := range(trustees) {
			tslice[j] = trustees[j].Coder.TrusteeEncode(payloadlen)
		}

		// Relay processing
		relay.Coder.DecodeStart(payloadlen, relay.Histoream)
		for i := range(clients) {
			relay.Coder.DecodeClient(cslice[i])
		}
		for j := range(trustees) {
			relay.Coder.DecodeTrustee(tslice[j])
		}
		outb := relay.Coder.DecodeCell()

		//os.Stdout.Write(outb)
		if outb == nil || len(outb) != payloadlen ||
			!bytes.Equal(inb[:payloadlen], outb[:payloadlen]) {
			panic("oops, data corrupted")
		}

		ncells++
		nbytes += payloadlen
	}
	end := time.Now()
	fmt.Printf("Time %f cells %d bytes %d nclients %d ntrustees %d\n",
			float64(end.Sub(beg)) / 1000000000.0,
			ncells, nbytes, nclients, ntrustees)
}

