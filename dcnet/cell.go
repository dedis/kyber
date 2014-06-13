package dcnet

import (
	"os"
	"fmt"
	"bytes"
	"crypto/cipher"
	"dissent/crypto"
)

// Cell encoding, decoding, and accountability interface.
// One instance per series.
// Designed to support multiple alternative cell encoding methods,
// some for single-owner cells (in which only one key-holder transmits),
// others for multi-owner cells (for transmit-request bitmaps for example).
type CellCoder interface {

	///// Client and Trustee methods /////

	Setup(suite crypto.Suite, peerstreams []cipher.Stream)

	// Encode a ciphertext slice for the current cell,
	// transmitting the optional payload if non-nil.
	EncodeSlice(payload []byte, cellsize int) []byte


	///// Relay methods /////

	// Initialize per-cell decoding state for the next cell
	DecodeStart(cellsize int)

	// Combine a client's or trustee's ciphertext slice into this cell.
	// This decoding could be done in the background for parallelism;
	// it doesn't have to be finished until DecodeFinal() is called.
	DecodeSlice(slice []byte)

	// Combine all client and trustee slices provided via DecodeSlice(),
	// to reveal the anonymized plaintext for this cell.
	DecodeCell() []byte
}


type CellFactory func() CellCoder


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

func (n *testnode) nodeSetup(name string, peerkeys []crypto.Point,
				factory CellFactory) {
	n.name = name
	println("Setup",name)

	// Form Diffie-Hellman master secret shared with each peer,
	// and a pseudorandom master stream derived from each.
	n.npeers = len(peerkeys)
	n.peerkeys = peerkeys
	n.peerstreams = make([]cipher.Stream, n.npeers)
	for j := range(peerkeys) {
		dh := n.suite.Point().Encrypt(peerkeys[j], n.spri)
		println(" DH",dh.String())
		n.peerstreams[j] = crypto.PointStream(n.suite, dh)
	}

	// Setup the cell coder
	n.coder = factory()
	n.coder.Setup(n.suite, n.peerstreams)
}

func TestCellCoder(factory CellFactory) {

	suite := crypto.NewAES128SHA256P256()

	nclients := 3
	ntrustees := 2

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
		clients[i].nodeSetup(fmt.Sprintf("Client%d",i), tkeys, factory)
	}
	for j := range(trustees) {
		trustees[j].nodeSetup(fmt.Sprintf("Trustee%d",j), ckeys, factory)
	}

	// Get some data to transmit
	println("Simulating DC-nets")
	payloadlen := 128
	inb := make([]byte, payloadlen)
	inf,_ := os.Open("cell.go")
	for {
		n,_ := inf.Read(inb)
		if n <= 0 {
			break
		}
		payloadlen = n

		// Process one cell worth of DC-nets activity
		cellsize := payloadlen		 // XXX some encodings expand

		// For simplicity the relay will consume slices
		// as clients and trustees produce them.
		relay.coder.DecodeStart(cellsize)

		// first client (owner) gets the payload data
		p := make([]byte, payloadlen)
		copy(p, inb)
		for i := range(clients) {
			slice := clients[i].coder.EncodeSlice(p, cellsize)
			p = nil		// for remaining clients
			relay.coder.DecodeSlice(slice)
		}
		for i := range(trustees) {
			slice := trustees[i].coder.EncodeSlice(nil, cellsize)
			relay.coder.DecodeSlice(slice)
		}

		outb := relay.coder.DecodeCell()
		os.Stdout.Write(outb)
		if !bytes.Equal(inb[:payloadlen], outb[:payloadlen]) {
			panic("oops, data corrupted")
		}
	}
}

