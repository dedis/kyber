package proof

import (
	"fmt"
	"testing"
	//"encoding/hex"
	"crypto/cipher"
	"dissent/crypto"
)

type node struct {
	i int
	done bool

	x crypto.Secret
	X crypto.Point

	proto StarProtocol
	outbox chan []byte
	inbox chan [][]byte
}

func (n *node) Step(msg []byte) ([][]byte,error) {

	n.outbox <- msg
	msgs := <- n.inbox
	return msgs,nil
}

func (n *node) Random() cipher.Stream {
	return crypto.RandomStream
}

func runNode(n *node) {
	errs := func(StarContext)[]error(n.proto)(n)

	fmt.Printf("node %d finished\n", n.i)
	for i := range(errs) {
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

	suite := crypto.NewAES128SHA256P256()
	rand := crypto.RandomStream

	svar := []string{"x","y"}
	pvar := []string{"B","X","Y","R"}
	B := suite.Point().Base()

	// Make some keypairs
	nodes := make([]*node, nnodes)
	for i := 0; i < nnodes; i++ {
		n := &node{}
		nodes[i] = n
		n.i = i
		n.x = suite.Secret().Pick(rand)
		n.X = suite.Point().Mul(nil,n.x)
	}

	// Make some provers and verifiers
	for i := 0; i < nnodes; i++ {
		n := nodes[i]
		prf := NewProof(suite,svar,pvar)
		pred := prf.Log("X","x","B")
		sval := map[string]crypto.Secret{ "x":n.x }
		pval := map[string]crypto.Point{"B":B, "X":n.X}
		prover := prf.Prover(pred, sval, pval)

		vi := (i+2)%nnodes	// which node's proof to verify
		vprf := NewProof(suite,svar,pvar)
		vrfs := make([]Verifier, nnodes)
		vpred := vprf.Log("X","x","B")
		vpval := map[string]crypto.Point{"B":B, "X":nodes[vi].X}
		vrfs[vi] = vprf.Verifier(vpred, vpval)

		n.proto = DeniableProver(suite, i, prover, vrfs)
		n.outbox = make(chan []byte)
		n.inbox = make(chan [][]byte)

		go runNode(n)
	}

	for {
		// Collect messages from all still-active nodes
		msgs := make([][]byte, nnodes)
		done := true
		for i := range(nodes) {
			n := nodes[i]
			if n == nil {
				continue
			}
			done = false
			msgs[i] = <- n.outbox
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
		for i := range(nodes) {
			if nodes[i] != nil {
				nodes[i].inbox <- msgs
			}
		}
	}
}

