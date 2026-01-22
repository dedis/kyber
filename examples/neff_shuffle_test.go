package examples

import (
	"testing"

	"github.com/stretchr/testify/require"
	"go.dedis.ch/kyber/v4"
	"go.dedis.ch/kyber/v4/group/edwards25519"
	kproof "go.dedis.ch/kyber/v4/proof"
	"go.dedis.ch/kyber/v4/shuffle"
)

var suite = edwards25519.NewBlakeSHA256Ed25519()

// This example illustrates how to use the Neff shuffle protocol with simple,
// single pairs.
func Test_Example_Neff_Shuffle_Simple(t *testing.T) {
	numPairs := 3

	// generate random pairs
	ks := make([]kyber.Point, numPairs)
	cs := make([]kyber.Point, numPairs)

	for i := range numPairs {
		c := suite.Point().Mul(suite.Scalar().Pick(suite.RandomStream()), nil)
		k := suite.Point().Mul(suite.Scalar().Pick(suite.RandomStream()), nil)

		ks[i] = k
		cs[i] = c
	}

	// shuffle the pairs
	xx, yy, prover := shuffle.Shuffle(suite, nil, nil, ks, cs, suite.RandomStream())

	// compute the proof
	proof, err := kproof.HashProve(suite, "PairShuffle", prover)
	require.NoError(t, err)

	// check the proof
	verifier := shuffle.Verifier(suite, nil, nil, ks, cs, xx, yy)

	err = kproof.HashVerify(suite, "PairShuffle", verifier, proof)
	require.NoError(t, err)
}

// This example illustrates how to use the Neff shuffle protocol on sequences of
// pairs. The single pair protocol (see above) uses as inputs one-dimensional
// slices. This variation uses 2-dimensional slices, where the number of columns
// defines the number of sequences, and the number of rows defines the length of
// sequences. There is also a difference when getting the prover. In this
// variation the Shuffle function doesn't directly return a prover, but a
// function to get it. This is because the verifier must provide a slice of
// random numbers to the prover.
func Test_Example_Neff_Shuffle_Sequence(t *testing.T) {
	sequenceLen := 3
	numSequences := 3

	X := make([][]kyber.Point, numSequences)
	Y := make([][]kyber.Point, numSequences)

	// generate random sequences
	for i := range numSequences {
		xs := make([]kyber.Point, sequenceLen)
		ys := make([]kyber.Point, sequenceLen)

		for j := range sequenceLen {
			xs[j] = suite.Point().Mul(suite.Scalar().Pick(suite.RandomStream()), nil)
			ys[j] = suite.Point().Mul(suite.Scalar().Pick(suite.RandomStream()), nil)
		}

		X[i] = xs
		Y[i] = ys
	}

	// shuffle sequences
	XX, YY, getProver := shuffle.SequencesShuffle(suite, nil, nil, X, Y, suite.RandomStream())

	// compute the proof
	NQ := len(X)
	e := make([]kyber.Scalar, NQ)
	for j := range NQ {
		e[j] = suite.Scalar().Pick(suite.RandomStream())
	}

	prover, err := getProver(e)
	require.NoError(t, err)

	proof, err := kproof.HashProve(suite, "SequencesShuffle", prover)
	require.NoError(t, err)

	// check the proof
	XXUp, YYUp, XXDown, YYDown := shuffle.GetSequenceVerifiable(suite, X, Y, XX, YY, e)

	verifier := shuffle.Verifier(suite, nil, nil, XXUp, YYUp, XXDown, YYDown)

	err = kproof.HashVerify(suite, "SequencesShuffle", verifier, proof)
	require.NoError(t, err)
}
