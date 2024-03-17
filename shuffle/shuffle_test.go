package shuffle

import (
	"crypto/cipher"
	"testing"

	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/kyber/v3/group/edwards25519"
	"go.dedis.ch/kyber/v3/proof"
	"go.dedis.ch/kyber/v3/xof/blake2xb"
)

var k = 5
var NQ = 6
var N = 1

func TestShufflePair(t *testing.T) {
	s := edwards25519.NewBlakeSHA256Ed25519WithRand(blake2xb.New(nil))
	pairShuffleTest(s, k, N)
}

func TestShuffleSequence(t *testing.T) {
	s := edwards25519.NewBlakeSHA256Ed25519WithRand(blake2xb.New(nil))
	sequenceShuffleTest(s, k, NQ, N)
}

func setShuffleKeyPairs(rand cipher.Stream, suite Suite, k int) (kyber.Scalar, kyber.Point, []kyber.Scalar, []kyber.Point) {
	// Create a "server" private/public keypair
	h0 := suite.Scalar().Pick(rand)
	h1 := suite.Point().Mul(h0, nil)

	// Create a set of ephemeral "client" keypairs to shuffle
	c0 := make([]kyber.Scalar, k)
	c1 := make([]kyber.Point, k)

	for i := 0; i < k; i++ {
		c0[i] = suite.Scalar().Pick(rand)
		c1[i] = suite.Point().Mul(c0[i], nil)

	}

	return h0, h1, c0, c1
}

func pairShuffleTest(suite Suite, k, n int) {
	rand := suite.RandomStream()
	_, h1, _, c1 := setShuffleKeyPairs(rand, suite, k)

	// ElGamal-encrypt all these keypairs with the "server" key
	x := make([]kyber.Point, k)
	y := make([]kyber.Point, k)
	r := suite.Scalar() // temporary
	for i := 0; i < k; i++ {
		r.Pick(rand)
		x[i] = suite.Point().Mul(r, nil)
		y[i] = suite.Point().Mul(r, h1) // ElGamal blinding factor
		y[i].Add(y[i], c1[i])           // Encrypted client public key
	}

	// Repeat only the actual shuffle portion for benchmark purposes.
	for i := 0; i < n; i++ {

		// Do a key-shuffle
		Xbar, Ybar, prover := Shuffle(suite, nil, h1, x, y, rand)
		prf, err := proof.HashProve(suite, "PairShuffle", prover)
		if err != nil {
			panic("Shuffle proof failed: " + err.Error())
		}

		// Check it
		verifier := Verifier(suite, nil, h1, x, y, Xbar, Ybar)
		err = proof.HashVerify(suite, "PairShuffle", verifier, prf)
		if err != nil {
			panic("Shuffle verify failed: " + err.Error())
		}
	}
}

func sequenceShuffleTest(suite Suite, k, NQ, N int) {
	rand := suite.RandomStream()
	_, h1, _, c1 := setShuffleKeyPairs(rand, suite, k)

	X := make([][]kyber.Point, NQ)
	Y := make([][]kyber.Point, NQ)

	// generate random sequences
	for i := 0; i < NQ; i++ {
		xs := make([]kyber.Point, k)
		ys := make([]kyber.Point, k)

		for j := 0; j < k; j++ {
			xs[j] = suite.Point().Mul(suite.Scalar().Pick(suite.RandomStream()), nil)
			ys[j] = suite.Point().Mul(suite.Scalar().Pick(suite.RandomStream()), nil)
		}

		X[i] = xs
		Y[i] = ys
	}

	// ElGamal-encrypt all these keypairs with the "server" key
	r := suite.Scalar() // temporary
	for j := 0; j < NQ; j++ {
		for i := 0; i < k; i++ {
			r.Pick(rand)
			X[j][i] = suite.Point().Mul(r, nil)
			Y[j][i] = suite.Point().Mul(r, h1) // ElGamal blinding factor
			Y[j][i].Add(Y[j][i], c1[i])        // Encrypted client public key
		}
	}

	// Repeat only the actual shuffle portion for benchmark purposes.
	for i := 0; i < N; i++ {

		// Do a key-shuffle
		XX, YY, getProver := SequencesShuffle(suite, nil, h1, X, Y, rand)

		e := make([]kyber.Scalar, NQ)
		for j := 0; j < NQ; j++ {
			e[j] = suite.Scalar().Pick(suite.RandomStream())
		}

		prover, err := getProver(e)
		if err != nil {
			panic("failed to get prover: " + err.Error())
		}

		prf, err := proof.HashProve(suite, "PairShuffle", prover)
		if err != nil {
			panic("failed to hashProve: " + err.Error())
		}

		XXUp, YYUp, XXDown, YYDown := GetSequenceVerifiable(suite, X, Y, XX, YY, e)

		// Check it
		verifier := Verifier(suite, nil, h1, XXUp, YYUp, XXDown, YYDown)

		err = proof.HashVerify(suite, "PairShuffle", verifier, prf)
		if err != nil {
			panic("failed to hashVerify: " + err.Error())
		}
	}
}
