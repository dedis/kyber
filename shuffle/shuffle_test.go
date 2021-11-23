package shuffle

import (
	"testing"

	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/kyber/v3/group/edwards25519"
	"go.dedis.ch/kyber/v3/proof"
	"go.dedis.ch/kyber/v3/xof/blake2xb"
)

var k = 5
var NQ = 6
var N = 10

func TestShufflePair(t *testing.T) {
	s := edwards25519.NewBlakeSHA256Ed25519WithRand(blake2xb.New(nil))
	pairShuffleTest(s, k, N)
}

func TestShuffleSequence(t *testing.T) {
	s := edwards25519.NewBlakeSHA256Ed25519WithRand(blake2xb.New(nil))
	sequenceShuffleTest(s, k, NQ, N)
}

func pairShuffleTest(suite Suite, k, N int) {
	rand := suite.RandomStream()

	// Create a "server" private/public keypair
	h := suite.Scalar().Pick(rand)
	H := suite.Point().Mul(h, nil)

	// Create a set of ephemeral "client" keypairs to shuffle
	c := make([]kyber.Scalar, k)
	C := make([]kyber.Point, k)
	//	fmt.Println("\nclient keys:")
	for i := 0; i < k; i++ {
		c[i] = suite.Scalar().Pick(rand)
		C[i] = suite.Point().Mul(c[i], nil)
		//		fmt.Println(" "+C[i].String())
	}

	// ElGamal-encrypt all these keypairs with the "server" key
	X := make([]kyber.Point, k)
	Y := make([]kyber.Point, k)
	r := suite.Scalar() // temporary
	for i := 0; i < k; i++ {
		r.Pick(rand)
		X[i] = suite.Point().Mul(r, nil)
		Y[i] = suite.Point().Mul(r, H) // ElGamal blinding factor
		Y[i].Add(Y[i], C[i])           // Encrypted client public key
	}

	// Repeat only the actual shuffle portion for test purposes.
	for i := 0; i < N; i++ {

		// Do a key-shuffle
		Xbar, Ybar, prover := Shuffle(suite, nil, H, X, Y, rand)
		prf, err := proof.HashProve(suite, "PairShuffle", prover)
		if err != nil {
			panic("Shuffle proof failed: " + err.Error())
		}
		//fmt.Printf("proof:\n%s\n",hex.Dump(prf))

		// Check it
		verifier := Verifier(suite, nil, H, X, Y, Xbar, Ybar)
		err = proof.HashVerify(suite, "PairShuffle", verifier, prf)
		if err != nil {
			panic("Shuffle verify failed: " + err.Error())
		}
	}
}

func sequenceShuffleTest(suite Suite, k, NQ, N int) {
	rand := suite.RandomStream()

	// Create a "server" private/public keypair
	h := suite.Scalar().Pick(rand)
	H := suite.Point().Mul(h, nil)

	// Create a set of ephemeral "client" keypairs to shuffle
	c := make([]kyber.Scalar, k)
	C := make([]kyber.Point, k)

	for i := 0; i < k; i++ {
		c[i] = suite.Scalar().Pick(rand)
		C[i] = suite.Point().Mul(c[i], nil)
		//		fmt.Println(" "+C[i].String())
	}

	X := make([][]kyber.Point, NQ)
	Y := make([][]kyber.Point, NQ)

	// generate random sequences

	for i := 0; i < NQ; i++ {
		xs := make([]kyber.Point, k)
		ys := make([]kyber.Point, k)

		for i := 0; i < k; i++ {
			xs[i] = suite.Point().Mul(suite.Scalar().Pick(suite.RandomStream()), nil)
			ys[i] = suite.Point().Mul(suite.Scalar().Pick(suite.RandomStream()), nil)
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
			Y[j][i] = suite.Point().Mul(r, H) // ElGamal blinding factor
			Y[j][i].Add(Y[j][i], C[i])        // Encrypted client public key
		}
	}

	// Repeat only the actual shuffle portion for test purposes.
	for i := 0; i < N; i++ {

		// Do a key-shuffle
		XX, YY, getProver := SequencesShuffle(suite, nil, H, X, Y, rand)

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
		verifier := Verifier(suite, nil, H, XXUp, YYUp, XXDown, YYDown)

		err = proof.HashVerify(suite, "PairShuffle", verifier, prf)
		if err != nil {
			panic("failed to hashVerify: " + err.Error())
		}
	}
}
