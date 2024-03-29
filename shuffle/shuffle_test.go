package shuffle

import (
	"crypto/cipher"
	"testing"

	"github.com/stretchr/testify/assert"
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

func TestShuffleInvalidPair(t *testing.T) {
	s := edwards25519.NewBlakeSHA256Ed25519WithRand(blake2xb.New(nil))
	pairInvalidShuffleTest(t, s, k)
}

func TestShuffleSequence(t *testing.T) {
	s := edwards25519.NewBlakeSHA256Ed25519WithRand(blake2xb.New(nil))
	sequenceShuffleTest(s, k, NQ, N)
}

func TestInvalidShuffleSequence(t *testing.T) {
	s := edwards25519.NewBlakeSHA256Ed25519WithRand(blake2xb.New(nil))
	sequenceInvalidShuffleTest(t, s, k, NQ)
}

func setShuffleKeyPairs(rand cipher.Stream, suite Suite, k int) (kyber.Point, []kyber.Point) {
	// Create a "server" private/public keypair
	h0 := suite.Scalar().Pick(rand)
	h1 := suite.Point().Mul(h0, nil)

	// Create a set of ephemeral "client" keypairs to shuffle
	c1 := make([]kyber.Point, k)

	for i := 0; i < k; i++ {
		c0 := suite.Scalar().Pick(rand)
		c1[i] = suite.Point().Mul(c0, nil)
	}

	return h1, c1
}

func elGamalEncryptPair(
	rand cipher.Stream,
	suite Suite,
	c []kyber.Point,
	h kyber.Point, k int) ([]kyber.Point, []kyber.Point) {

	// ElGamal-encrypt all these keypairs with the "server" key
	x := make([]kyber.Point, k)
	y := make([]kyber.Point, k)
	r := suite.Scalar() // temporary
	for i := 0; i < k; i++ {
		r.Pick(rand)
		x[i] = suite.Point().Mul(r, nil)
		y[i] = suite.Point().Mul(r, h) // ElGamal blinding factor
		y[i].Add(y[i], c[i])           // Encrypted client public key
	}

	return x, y
}

func pairShuffleTest(suite Suite, k, n int) {
	rand := suite.RandomStream()
	h, c := setShuffleKeyPairs(rand, suite, k)
	x, y := elGamalEncryptPair(rand, suite, c, h, k)

	// Repeat only the actual shuffle portion for benchmark purposes.
	for i := 0; i < n; i++ {
		// Do a key-shuffle
		Xbar, Ybar, prover := Shuffle(suite, nil, h, x, y, rand)
		prf, err := proof.HashProve(suite, "PairShuffle", prover)
		if err != nil {
			panic("Shuffle proof failed: " + err.Error())
		}

		// Check it
		verifier := Verifier(suite, nil, h, x, y, Xbar, Ybar)
		err = proof.HashVerify(suite, "PairShuffle", verifier, prf)
		if err != nil {
			panic("Shuffle verify failed: " + err.Error())
		}
	}
}

func pairInvalidShuffleTest(t *testing.T, suite Suite, k int) {
	rand := suite.RandomStream()
	h, c := setShuffleKeyPairs(rand, suite, k)
	x, y := elGamalEncryptPair(rand, suite, c, h, k)

	// Do a key-shuffle
	Xbar, Ybar, prover := Shuffle(suite, nil, h, x, y, rand)

	// Corrupt the shuffle
	Xbar[1], Xbar[0] = Xbar[0], Xbar[1]

	prf, err := proof.HashProve(suite, "PairShuffle", prover)
	assert.Nil(t, err)

	// Check it
	verifier := Verifier(suite, nil, h, x, y, Xbar, Ybar)
	err = proof.HashVerify(suite, "PairShuffle", verifier, prf)
	assert.Error(t, err)
}

func generateAndEncryptRandomSequences(
	rand cipher.Stream,
	suite Suite,
	h kyber.Point,
	c []kyber.Point,
	k int) ([][]kyber.Point, [][]kyber.Point) {
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
			Y[j][i] = suite.Point().Mul(r, h) // ElGamal blinding factor
			Y[j][i].Add(Y[j][i], c[i])        // Encrypted client public key
		}
	}

	return X, Y
}

func sequenceShuffleTest(suite Suite, k, NQ, N int) {
	rand := suite.RandomStream()
	h, c := setShuffleKeyPairs(rand, suite, k)
	X, Y := generateAndEncryptRandomSequences(rand, suite, h, c, k)

	// Repeat only the actual shuffle portion for benchmark purposes.
	for i := 0; i < N; i++ {

		// Do a key-shuffle
		XX, YY, getProver := SequencesShuffle(suite, nil, h, X, Y, rand)

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
		verifier := Verifier(suite, nil, h, XXUp, YYUp, XXDown, YYDown)

		err = proof.HashVerify(suite, "PairShuffle", verifier, prf)
		if err != nil {
			panic("failed to hashVerify: " + err.Error())
		}
	}
}

func sequenceInvalidShuffleTest(t *testing.T, suite Suite, k, NQ int) {
	rand := suite.RandomStream()
	h, c := setShuffleKeyPairs(rand, suite, k)
	X, Y := generateAndEncryptRandomSequences(rand, suite, h, c, k)

	// Do a key-shuffle
	XX, YY, getProver := SequencesShuffle(suite, nil, h, X, Y, rand)

	// Corrupt original inputs
	X[0][0], Y[0][0] = X[0][1], Y[0][1]

	e := make([]kyber.Scalar, NQ)
	for j := 0; j < NQ; j++ {
		e[j] = suite.Scalar().Pick(suite.RandomStream())
	}

	prover, err := getProver(e)
	assert.Nil(t, err)

	prf, err := proof.HashProve(suite, "PairShuffle", prover)
	assert.Nil(t, err)

	XXUp, YYUp, XXDown, YYDown := GetSequenceVerifiable(suite, X, Y, XX, YY, e)

	// Check it
	verifier := Verifier(suite, nil, h, XXUp, YYUp, XXDown, YYDown)

	err = proof.HashVerify(suite, "PairShuffle", verifier, prf)
	assert.Error(t, err)
}
