package shuffle

import (
	"testing"

	"go.dedis.ch/kyber/v4"
	"go.dedis.ch/kyber/v4/group/edwards25519"
	"go.dedis.ch/kyber/v4/proof"
	"go.dedis.ch/kyber/v4/xof/blake2xb"
)

func TestBiffle(_ *testing.T) {
	rand := blake2xb.New(nil)
	s := edwards25519.NewBlakeSHA256Ed25519WithRand(rand)
	biffleTest(s, N)
}

func TestInvalidBiffle(_ *testing.T) {
	rand := blake2xb.New(nil)
	s := edwards25519.NewBlakeSHA256Ed25519WithRand(rand)
	biffleInvalidTest(s)
}

func biffleTest(suite Suite, n int) {
	rand := suite.RandomStream()
	h, c := setShuffleKeyPairs(rand, suite, 2)

	// ElGamal-encrypt all these keypairs with the "server" key
	var X, Y [2]kyber.Point
	r := suite.Scalar() // temporary
	for i := range 2 {
		r.Pick(rand)
		X[i] = suite.Point().Mul(r, nil)
		Y[i] = suite.Point().Mul(r, h) // ElGamal blinding factor
		Y[i].Add(Y[i], c[i])           // Encrypted client public key
	}

	// Repeat only the actual shuffle portion for test purposes.
	for range n {
		// Do a key-shuffle
		Xbar, Ybar, prover := Biffle(suite, nil, h, X, Y, rand)
		prf, err := proof.HashProve(suite, "Biffle", prover)
		if err != nil {
			panic("Biffle proof failed: " + err.Error())
		}

		// Check it
		verifier := BiffleVerifier(suite, nil, h, X, Y, Xbar, Ybar)
		err = proof.HashVerify(suite, "Biffle", verifier, prf)
		if err != nil {
			panic("Biffle verify failed: " + err.Error())
		}
	}
}

func biffleInvalidTest(suite Suite) {
	rand := suite.RandomStream()
	h, c := setShuffleKeyPairs(rand, suite, 2)

	// ElGamal-encrypt all these keypairs with the "server" key
	var X, Y [2]kyber.Point
	r := suite.Scalar() // temporary
	for i := range 2 {
		r.Pick(rand)
		X[i] = suite.Point().Mul(r, nil)
		Y[i] = suite.Point().Mul(r, h) // ElGamal blinding factor
		Y[i].Add(Y[i], c[i])           // Encrypted client public key
	}

	// Do a key-shuffle
	Xbar, Ybar, prover := Biffle(suite, nil, h, X, Y, rand)
	prf, err := proof.HashProve(suite, "Biffle", prover)
	if err != nil {
		panic("Biffle proof failed: " + err.Error())
	}

	// Corrupt inputs
	X[0], Y[0] = X[1], Y[1]

	// Check it
	verifier := BiffleVerifier(suite, nil, h, X, Y, Xbar, Ybar)
	err = proof.HashVerify(suite, "Biffle", verifier, prf)
	if err == nil {
		panic("Biffle verify should have failed")
	}
}
