package proof

import (
	"fmt"
	"testing"
	//"encoding/hex"
	"github.com/dedis/crypto/abstract"
	"github.com/dedis/crypto/clique"
	"github.com/dedis/crypto/random"
	"github.com/dedis/crypto/suite"
)

var testSuite = suite.Default(nil)

type node struct {
	i    int
	done bool

	x abstract.Scalar
	X abstract.Point

	proto  clique.Protocol
	outbox chan []byte
	inbox  chan [][]byte
}

func (n *node) Step(msg []byte) ([][]byte, error) {

	n.outbox <- msg
	msgs := <-n.inbox
	return msgs, nil
}

func (n *node) Random() abstract.Cipher {
	return testSuite.Cipher(abstract.FreshKey)
}

func runNode(n *node) {
	errs := (func(clique.Context) []error)(n.proto)(n)

	fmt.Printf("node %d finished\n", n.i)
	for i := range errs {
		if errs[i] == nil {
			fmt.Printf("- (%d)%d: SUCCESS\n", n.i, i)
		} else {
			fmt.Printf("- (%d)%d: %s\n", n.i, i, errs[i])
		}
	}

	n.done = true
	n.outbox <- nil
}

func TestDeniable(t *testing.T) {
	nnodes := 5
	/*
		nmsgs := 5
		var p localProto

		nodes := [10][]Message{}

		// create the message pattern
		msg := make([][]Message, nnodes)
		for i := range(msg) {
			msg[i] := make([]Message, nmsgs)
			for j := range(msg[i]) {
			}
		}

		ctx := make([]localContext, nnodes)
		for i := range(ctx) {
			ctx[i].init()
		}
		for i := range(ctx) {
			go func() {
				// fill in our message
				buf :=
				msg[i].Put(
			}()
		}

		localProto.run()
	*/

	suite := testSuite
	rand := random.Fresh()
	B := suite.Point().Base()

	// Make some keypairs
	nodes := make([]*node, nnodes)
	for i := 0; i < nnodes; i++ {
		n := &node{}
		nodes[i] = n
		n.i = i
		n.x = suite.Scalar().Pick(nil, rand)
		n.X = suite.Point().BaseMul(n.x)
	}

	// Make some provers and verifiers
	for i := 0; i < nnodes; i++ {
		n := nodes[i]
		pred := Rep("X", "x", "B")
		sval := map[string]abstract.Scalar{"x": n.x}
		pval := map[string]abstract.Point{"B": B, "X": n.X}
		prover := pred.Prover(suite.Context(), sval, pval, nil)

		vi := (i + 2) % nnodes // which node's proof to verify
		vrfs := make([]Verifier, nnodes)
		vpred := Rep("X", "x", "B")
		vpval := map[string]abstract.Point{"B": B, "X": nodes[vi].X}
		vrfs[vi] = vpred.Verifier(suite.Context(), vpval)

		n.proto = DeniableProver(suite.Context(), i, prover, vrfs)
		n.outbox = make(chan []byte)
		n.inbox = make(chan [][]byte)

		go runNode(n)
	}

	for {
		// Collect messages from all still-active nodes
		msgs := make([][]byte, nnodes)
		done := true
		for i := range nodes {
			n := nodes[i]
			if n == nil {
				continue
			}
			done = false
			msgs[i] = <-n.outbox
			//fmt.Printf("from %d: (%d bytes)\n%s", i,
			//	len(msgs[i]), hex.Dump(msgs[i]))
			if n.done {
				nodes[i] = nil
			}
		}
		if done {
			break
		}

		// Distribute all messages to all still-active nodes
		for i := range nodes {
			if nodes[i] != nil {
				nodes[i].inbox <- msgs
			}
		}
	}
}
