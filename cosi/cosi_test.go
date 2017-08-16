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
		m, err := NewMask(testSuite, publics, publics[i])
		if err != nil {
			t.Fatal(err)
		}
		masks = append(masks, m)
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
	aggV, aggMask, err := AggregateCommitments(testSuite, V, byteMasks)
	if err != nil {
		t.Fatal(err)
	}

	// Set aggregate mask in nodes
	for i := 0; i < n; i++ {
		masks[i].SetMask(aggMask)
	}

	// Compute challenge
	var c []abstract.Scalar
	for i := 0; i < n; i++ {
		ci, err := Challenge(testSuite, aggV, masks[i].AggregatePublic, message)
		if err != nil {
			t.Fatal(err)
		}
		c = append(c, ci)
	}

	// Compute responses
	var r []abstract.Scalar
	for i := 0; i < n; i++ {
		ri, _ := Response(testSuite, privates[i], v[i], c[i])
		r = append(r, ri)
	}

	// Aggregate responses
	aggr, err := AggregateResponses(testSuite, r)
	if err != nil {
		t.Fatal(err)
	}

	for i := 0; i < n; i++ {
		// Sign
		sig, err := Sign(testSuite, aggV, aggr, masks[i])
		if err != nil {
			t.Fatal(err)
		}
		// Verify (using default policy)
		if err := Verify(testSuite, publics, message, sig, nil); err != nil {
			t.Fatal(err)
		}
	}
}

func TestCoSiThreshold(t *testing.T) {
	n := 5
	f := 2
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
	for i := 0; i < n-f; i++ {
		m, err := NewMask(testSuite, publics, publics[i])
		if err != nil {
			t.Fatal(err)
		}
		masks = append(masks, m)
		byteMasks = append(byteMasks, masks[i].Mask())
	}

	// Compute commitments
	var v []abstract.Scalar // random
	var V []abstract.Point  // commitment
	for i := 0; i < n-f; i++ {
		x, X := Commit(testSuite, nil)
		v = append(v, x)
		V = append(V, X)
	}

	// Aggregate commitments
	aggV, aggMask, err := AggregateCommitments(testSuite, V, byteMasks)
	if err != nil {
		t.Fatal(err)
	}

	// Set aggregate mask in nodes
	for i := 0; i < n-f; i++ {
		masks[i].SetMask(aggMask)
	}

	// Compute challenge
	var c []abstract.Scalar
	for i := 0; i < n-f; i++ {
		ci, err := Challenge(testSuite, aggV, masks[i].AggregatePublic, message)
		if err != nil {
			t.Fatal(err)
		}
		c = append(c, ci)
	}

	// Compute responses
	var r []abstract.Scalar
	for i := 0; i < n-f; i++ {
		ri, _ := Response(testSuite, privates[i], v[i], c[i])
		r = append(r, ri)
	}

	// Aggregate responses
	aggr, err := AggregateResponses(testSuite, r)
	if err != nil {
		t.Fatal(err)
	}

	for i := 0; i < n-f; i++ {
		// Sign
		sig, err := Sign(testSuite, aggV, aggr, masks[i])
		if err != nil {
			t.Fatal(err)
		}
		// Verify (using threshold policy)
		if err := Verify(testSuite, publics, message, sig, &ThresholdPolicy{n - f}); err != nil {
			t.Fatal(err)
		}
	}
}
