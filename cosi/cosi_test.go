package cosi

import (
	"testing"

	"github.com/dedis/kyber/abstract"
	"github.com/dedis/kyber/config"
	"github.com/dedis/kyber/ed25519"
)

var testSuite = ed25519.NewAES128SHA256Ed25519(false)

func TestCoSi(t *testing.T) {
	n := 5
	message := []byte("Hello World Cosi")

	// Generate key pairs
	var kps []*config.KeyPair
	var privates []abstract.Scalar
	var publics []abstract.Point
	for i := 0; i < n; i++ {
		kp := config.NewKeyPair(testSuite)
		kps = append(kps, kp)
		privates = append(privates, kp.Secret)
		publics = append(publics, kp.Public)
	}

	// Init masks
	var masks []*Mask
	var byteMasks [][]byte
	for i := 0; i < n; i++ {
		masks = append(masks, NewMask(testSuite, publics))
		masks[i].SetMaskBit(i, true) // TODO: this has to go into the mask initialization somehow
		byteMasks = append(byteMasks, masks[i].mask)
	}

	// Compute commitments
	var v []abstract.Scalar // random
	var V []abstract.Point  // commitment
	for i := 0; i < n; i++ {
		x, X := Commit(testSuite, nil)
		v = append(v, x)
		V = append(V, X)
	}

	// Aggregate commitments
	aggV, aggMask, err := AggregateCommitments(testSuite, V, publics, byteMasks)
	if err != nil {
		t.Fatal(err)
	}

	// Set aggregate mask in nodes
	for i := 0; i < n; i++ {
		masks[i].SetMask(aggMask.mask)
	}

	// Compute challenge
	c, err := Challenge(testSuite, aggV, masks[0], message)
	if err != nil {
		t.Fatal(err)
	}

	// Compute responses
	var r []abstract.Scalar
	for i := 0; i < n; i++ {
		ri, _ := Response(testSuite, v[i], c, privates[i])
		r = append(r, ri)
	}

	// Aggregate responses
	aggr, err := AggregateResponses(testSuite, r)
	if err != nil {
		t.Fatal(err)
	}

	// Sign
	sig, err := Sign(testSuite, aggV, aggr, aggMask)
	if err != nil {
		t.Fatal(err)
	}

	// Verify
	if err := Verify(testSuite, publics, message, sig, CompletePolicy{}); err != nil {
		t.Fatal(err)
	}

}
