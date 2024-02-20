package shuffle

import (
	"crypto/cipher"
	"errors"
	"fmt"
	"math/big"

	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/kyber/v3/proof"
	"go.dedis.ch/kyber/v3/util/random"
)

// SequencesShuffle shuffles a sequence of ElGamal pairs based on Section 5 of
// "Verifiable Mixing (Shuffling) of ElGamal Pairs" by Andrew Neff (April 2004)
//
// The function expects X and Y to be the same dimension, with each row having
// the same length. It also expect X and Y to have at least one element. The
// function will panic if the expectations are not met.
//
// Dim X and Y: [<sequence length, j>, <number of sequences, i>]
//
// The number of rows defines the sequences length. The number of columns
// defines the number of sequences.
//
//	Seq 1  Seq 2  Seq 3
//	(0,0)  (0,1)  (0,2)
//	(1,0)  (1,1)  (1,2)
//	(2,0)  (2,1)  (2,2)
//
// # In the code coordinates are (j,i), where 0 ≤ j ≤ NQ-1, 0 ≤ i ≤ k-1
//
// Last coordinate is (NQ-1, k-1)
//
// Variable names are as representative to the paper as possible.
func SequencesShuffle(group kyber.Group, g, h kyber.Point, x, y [][]kyber.Point,
	rand cipher.Stream) (Xbar, Ybar [][]kyber.Point, getProver func(e []kyber.Scalar) (
	proof.Prover, error)) {

	err := assertXY(x, y)
	if err != nil {
		panic(fmt.Sprintf("invalid data: %v", err))
	}

	NQ := len(x)
	k := len(x[0])

	// Pick a random permutation used in ALL k ElGamal sequences. The permutation
	// (π) of an ElGamal pair at index i always outputs to the same index
	pi := make([]int, k)
	for i := 0; i < k; i++ {
		pi[i] = i
	}

	// Fisher–Yates shuffle
	for i := k - 1; i > 0; i-- {
		j := int(random.Int(big.NewInt(int64(i+1)), rand).Int64())
		if j != i {
			pi[i], pi[j] = pi[j], pi[i]
		}
	}

	// Pick a fresh ElGamal blinding factor β(j, i) for each ElGamal sequence
	// and each ElGamal pair
	beta := make([][]kyber.Scalar, NQ)
	for j := 0; j < NQ; j++ {
		beta[j] = make([]kyber.Scalar, k)
		for i := 0; i < k; i++ {
			beta[j][i] = group.Scalar().Pick(rand)
		}
	}

	// Perform the Shuffle
	Xbar = make([][]kyber.Point, NQ)
	Ybar = make([][]kyber.Point, NQ)

	for j := 0; j < NQ; j++ {
		Xbar[j] = make([]kyber.Point, k)
		Ybar[j] = make([]kyber.Point, k)

		for i := 0; i < k; i++ {
			Xbar[j][i] = group.Point().Mul(beta[j][pi[i]], g)
			Xbar[j][i].Add(Xbar[j][i], x[j][pi[i]])

			Ybar[j][i] = group.Point().Mul(beta[j][pi[i]], h)
			Ybar[j][i].Add(Ybar[j][i], y[j][pi[i]])
		}
	}

	getProver = func(e []kyber.Scalar) (proof.Prover, error) {
		// EGAR 2 (Prover) - Standard ElGamal k-shuffle proof: Knowledge of
		// (XUp, YUp), (XDown, YDown) and e[j]

		ps := PairShuffle{}
		ps.Init(group, k)

		if len(e) != NQ {
			return nil, fmt.Errorf("len(e) must be equal to NQ: %d != %d", len(e), NQ)
		}

		return func(ctx proof.ProverContext) error {
			// Need to consolidate beta to a one dimensional array
			beta2 := make([]kyber.Scalar, k)

			for i := 0; i < k; i++ {
				beta2[i] = group.Scalar().Mul(e[0], beta[0][i])

				for j := 1; j < NQ; j++ {
					beta2[i] = group.Scalar().Add(beta2[i],
						group.Scalar().Mul(e[j], beta[j][i]))
				}
			}

			XUp, YUp, _, _ := GetSequenceVerifiable(group, x, y, Xbar, Ybar, e)

			return ps.Prove(pi, g, h, beta2, XUp, YUp, rand, ctx)
		}, nil
	}

	return Xbar, Ybar, getProver
}

// assertXY checks that x, y have the same dimensions and at least one element
func assertXY(x, y [][]kyber.Point) error {
	if len(x) == 0 || len(x[0]) == 0 {
		return errors.New("X is empty")
	}
	if len(y) == 0 || len(y[0]) == 0 {
		return errors.New("Y is empty")
	}

	if len(x) != len(y) {
		return fmt.Errorf("X and Y have a different size: %d != %d", len(x), len(y))
	}

	expected := len(x[0])

	for i := range x {
		if len(x[i]) != expected {
			return fmt.Errorf("X[%d] has unexpected size: %d != %d", i, expected, len(x[i]))
		}
		if len(y[i]) != expected {
			return fmt.Errorf("Y[%d] has unexpected size: %d != %d", i, expected, len(y[i]))
		}
	}

	return nil
}

// GetSequenceVerifiable returns the consolidated input and output of sequence
// shuffling elements. Needed by the prover and verifier.
func GetSequenceVerifiable(group kyber.Group, x, y, xBar, yBar [][]kyber.Point, e []kyber.Scalar) (
	XUp, YUp, XDown, YDown []kyber.Point) {

	// EGAR1 (Verifier) - Consolidate input and output
	NQ := len(x)
	k := len(x[0])

	XUp = make([]kyber.Point, k)
	YUp = make([]kyber.Point, k)
	XDown = make([]kyber.Point, k)
	YDown = make([]kyber.Point, k)

	for i := 0; i < k; i++ {
		// No modification could be made for e[0] -> e[0] = 1 if one wanted -
		// Remark 7 in the paper
		XUp[i] = group.Point().Mul(e[0], x[0][i])
		YUp[i] = group.Point().Mul(e[0], y[0][i])

		XDown[i] = group.Point().Mul(e[0], xBar[0][i])
		YDown[i] = group.Point().Mul(e[0], yBar[0][i])

		for j := 1; j < NQ; j++ {
			XUp[i] = group.Point().Add(XUp[i],
				group.Point().Mul(e[j], x[j][i]))
			YUp[i] = group.Point().Add(YUp[i],
				group.Point().Mul(e[j], y[j][i]))

			XDown[i] = group.Point().Add(XDown[i],
				group.Point().Mul(e[j], xBar[j][i]))
			YDown[i] = group.Point().Add(YDown[i],
				group.Point().Mul(e[j], yBar[j][i]))
		}
	}

	return XUp, YUp, XDown, YDown
}
