package dcnet

import (
	"os"
	"fmt"
	"time"
	"bytes"
	"crypto/cipher"
	"dissent/crypto"
)

type testnode struct {

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

	coder CellCoder
}

func (n *testnode) nodeSetup(name string, peerkeys []crypto.Point) {
	n.name = name
	//println("Setup",name)

	// Form Diffie-Hellman master secret shared with each peer,
	// and a pseudorandom master stream derived from each.
	n.npeers = len(peerkeys)
	n.peerkeys = peerkeys
	n.peerstreams = make([]cipher.Stream, n.npeers)
	for j := range(peerkeys) {
		dh := n.suite.Point().Encrypt(peerkeys[j], n.spri)
		//println(" DH",dh.String())
		n.peerstreams[j] = crypto.PointStream(n.suite, dh)
	}
}

func TestCellCoder(factory CellFactory) {

	suite := crypto.NewAES128SHA256P256()

	nclients := 1
	ntrustees := 3

	nodes := make([]*testnode, nclients+ntrustees)
	base := suite.Point().Base()
	for i := range(nodes) {
		nodes[i] = new(testnode)
		nodes[i].suite = suite

		// Each client and trustee gets a session keypair
		nodes[i].spri = suite.Secret().Pick(crypto.RandomStream)
		nodes[i].spub = suite.Point().Encrypt(base, nodes[i].spri)

		nodes[i].coder = factory()
	}

	clients := nodes[:nclients]
	trustees := nodes[nclients:]

	relay := new(testnode)
	relay.name = "Relay"
	relay.coder = factory()

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
	opri := suite.Secret().Pick(crypto.RandomStream)
	opub := suite.Point().Encrypt(base, opri)
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
		n.coder = factory()
		n.coder.ClientSetup(suite, n.peerstreams)
	}
	tinfo := make([][]byte, ntrustees)
	for j := range(trustees) {
		n := trustees[j]
		n.nodeSetup(fmt.Sprintf("Trustee%d",j), ckeys)
		n.coder = factory()
		tinfo[j] = n.coder.TrusteeSetup(suite, n.peerstreams)
	}
	relay.coder.RelaySetup(suite, tinfo)

	// Create a set of fake history streams for the relay and clients
	hist := []byte("xyz")
	relayhist := crypto.HashStream(suite, hist)
	clienthist := make([]cipher.Stream, nclients)
	for i := range(clienthist) {
		clienthist[i] = crypto.HashStream(suite, hist)
	}

	// Get some data to transmit
	println("Simulating DC-nets")
	payloadlen := 1500
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
			cslice[i] = clients[i].coder.ClientEncode(p, payloadlen,
						clienthist[i])
			p = nil		// for remaining clients
		}
		for j := range(trustees) {
			tslice[j] = trustees[j].coder.TrusteeEncode(payloadlen)
		}

		// Relay processing
		relay.coder.DecodeStart(payloadlen, relayhist)
		for i := range(clients) {
			relay.coder.DecodeClient(cslice[i])
		}
		for j := range(trustees) {
			relay.coder.DecodeTrustee(tslice[j])
		}
		outb := relay.coder.DecodeCell()

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

