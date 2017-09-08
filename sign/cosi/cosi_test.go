package cosi

import (
	"testing"

	"gopkg.in/dedis/kyber.v1"
	"gopkg.in/dedis/kyber.v1/group/edwards25519"
	"gopkg.in/dedis/kyber.v1/util/key"
)

var testGroup = edwards25519.NewAES128SHA256Ed25519()

func TestCoSi(t *testing.T) {
	n := 5
	message := []byte("Hello World Cosi")

	// Generate key pairs
	var kps []*key.Pair
	var privates []kyber.Scalar
	var publics []kyber.Point
	for i := 0; i < n; i++ {
		kp := key.NewKeyPair(testGroup)
		kps = append(kps, kp)
		privates = append(privates, kp.Secret)
		publics = append(publics, kp.Public)
	}

	// Init masks
	var masks []*Mask
	var byteMasks [][]byte
	for i := 0; i < n; i++ {
		m, err := NewMask(testGroup, publics, publics[i])
		if err != nil {
			t.Fatal(err)
		}
		masks = append(masks, m)
		byteMasks = append(byteMasks, masks[i].mask)
	}

	// Compute commitments
	var v []kyber.Scalar // random
	var V []kyber.Point  // commitment
	for i := 0; i < n; i++ {
		x, X := Commit(testGroup, nil)
		v = append(v, x)
		V = append(V, X)
	}

	// Aggregate commitments
	aggV, aggMask, err := AggregateCommitments(testGroup, V, byteMasks)
	if err != nil {
		t.Fatal(err)
	}

	// Set aggregate mask in nodes
	for i := 0; i < n; i++ {
		masks[i].SetMask(aggMask)
	}

	// Compute challenge
	var c []kyber.Scalar
	for i := 0; i < n; i++ {
		ci, err := Challenge(testGroup, aggV, masks[i].AggregatePublic, message)
		if err != nil {
			t.Fatal(err)
		}
		c = append(c, ci)
	}

	// Compute responses
	var r []kyber.Scalar
	for i := 0; i < n; i++ {
		ri, _ := Response(testGroup, privates[i], v[i], c[i])
		r = append(r, ri)
	}

	// Aggregate responses
	aggr, err := AggregateResponses(testGroup, r)
	if err != nil {
		t.Fatal(err)
	}

	for i := 0; i < n; i++ {
		// Sign
		sig, err := Sign(testGroup, aggV, aggr, masks[i])
		if err != nil {
			t.Fatal(err)
		}
		// Verify (using default policy)
		if err := Verify(testGroup, publics, message, sig, nil); err != nil {
			t.Fatal(err)
		}
	}
}

func TestCoSiThreshold(t *testing.T) {
	n := 5
	f := 2
	message := []byte("Hello World Cosi")

	// Generate key pairs
	var kps []*key.Pair
	var privates []kyber.Scalar
	var publics []kyber.Point
	for i := 0; i < n; i++ {
		kp := key.NewKeyPair(testGroup)
		kps = append(kps, kp)
		privates = append(privates, kp.Secret)
		publics = append(publics, kp.Public)
	}

	// Init masks
	var masks []*Mask
	var byteMasks [][]byte
	for i := 0; i < n-f; i++ {
		m, err := NewMask(testGroup, publics, publics[i])
		if err != nil {
			t.Fatal(err)
		}
		masks = append(masks, m)
		byteMasks = append(byteMasks, masks[i].Mask())
	}

	// Compute commitments
	var v []kyber.Scalar // random
	var V []kyber.Point  // commitment
	for i := 0; i < n-f; i++ {
		x, X := Commit(testGroup, nil)
		v = append(v, x)
		V = append(V, X)
	}

	// Aggregate commitments
	aggV, aggMask, err := AggregateCommitments(testGroup, V, byteMasks)
	if err != nil {
		t.Fatal(err)
	}

	// Set aggregate mask in nodes
	for i := 0; i < n-f; i++ {
		masks[i].SetMask(aggMask)
	}

	// Compute challenge
	var c []kyber.Scalar
	for i := 0; i < n-f; i++ {
		ci, err := Challenge(testGroup, aggV, masks[i].AggregatePublic, message)
		if err != nil {
			t.Fatal(err)
		}
		c = append(c, ci)
	}

	// Compute responses
	var r []kyber.Scalar
	for i := 0; i < n-f; i++ {
		ri, _ := Response(testGroup, privates[i], v[i], c[i])
		r = append(r, ri)
	}

	// Aggregate responses
	aggr, err := AggregateResponses(testGroup, r)
	if err != nil {
		t.Fatal(err)
	}

	for i := 0; i < n-f; i++ {
		// Sign
		sig, err := Sign(testGroup, aggV, aggr, masks[i])
		if err != nil {
			t.Fatal(err)
		}
		// Verify (using threshold policy)
		if err := Verify(testGroup, publics, message, sig, &ThresholdPolicy{n - f}); err != nil {
			t.Fatal(err)
		}
	}
}
