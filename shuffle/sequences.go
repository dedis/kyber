package shuffle

import (
	"crypto/cipher"
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
// the same length. It also expect X and Y to have at least one element.
//
// Dim X and Y: [<sequence length, j>, <number of sequences, i>]
//
// The number of rows defines the sequences length. The number of columns
// defines the number of sequences.
//
//  Seq 1  Seq 2  Seq 3
//  (0,0)  (0,1)  (0,2)
//  (1,0)  (1,1)  (1,2)
//  (2,0)  (2,1)  (2,2)
//
// In the code coordinates are (j,i), where 0 ≤ j ≤ NQ-1, 0 ≤ i ≤ k-1
//
// Last coordinate is (NQ-1, k-1)
//
// Variable names are as representative to the paper as possible. Instead of
// representing (variable name with a bar on top), such as (X with a bar on top)
// with Xbar, we represent it with a repeating letter, such as XX
func SequencesShuffle(group kyber.Group, g, h kyber.Point, X, Y [][]kyber.Point,
	rand cipher.Stream) (XX, YY [][]kyber.Point, getProver func(e []kyber.Scalar) (
	proof.Prover, error)) {

	NQ := len(X)
	k := len(X[0])

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
	XX = make([][]kyber.Point, NQ)
	YY = make([][]kyber.Point, NQ)

	for j := 0; j < NQ; j++ {
		XX[j] = make([]kyber.Point, k)
		YY[j] = make([]kyber.Point, k)

		for i := 0; i < k; i++ {
			XX[j][i] = group.Point().Mul(beta[j][pi[i]], g)
			XX[j][i].Add(XX[j][i], X[j][pi[i]])

			YY[j][i] = group.Point().Mul(beta[j][pi[i]], h)
			YY[j][i].Add(YY[j][i], Y[j][pi[i]])
		}
	}

	getProver = func(e []kyber.Scalar) (proof.Prover, error) {
		// EGAR 2 (Prover) - Standard ElGamal k-shuffle proof: Knowledge of
		// (XXUp, YYUp), (XXDown, YYDown) and e[j]

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

			XXUp, YYUp, _, _ := GetSequenceVerifiable(group, X, Y, XX, YY, e)

			return ps.Prove(pi, g, h, beta2, XXUp, YYUp, rand, ctx)
		}, nil
	}

	return XX, YY, getProver
}

// GetSequenceVerifiable returns the consolidated input and output of sequence
// shuffling elements. Needed by the prover and verifier.
func GetSequenceVerifiable(group kyber.Group, X, Y, XX, YY [][]kyber.Point, e []kyber.Scalar) (
	XXUp, YYUp, XXDown, YYDown []kyber.Point) {

	// EGAR1 (Verifier) - Consolidate input and output
	NQ := len(X)
	k := len(X[0])

	XXUp = make([]kyber.Point, k)
	YYUp = make([]kyber.Point, k)
	XXDown = make([]kyber.Point, k)
	YYDown = make([]kyber.Point, k)

	for i := 0; i < k; i++ {
		// No modification could be made for e[0] -> e[0] = 1 if one wanted -
		// Remark 7 in the paper
		XXUp[i] = group.Point().Mul(e[0], X[0][i])
		YYUp[i] = group.Point().Mul(e[0], Y[0][i])

		XXDown[i] = group.Point().Mul(e[0], XX[0][i])
		YYDown[i] = group.Point().Mul(e[0], YY[0][i])

		for j := 1; j < NQ; j++ {
			XXUp[i] = group.Point().Add(XXUp[i],
				group.Point().Mul(e[j], X[j][i]))
			YYUp[i] = group.Point().Add(YYUp[i],
				group.Point().Mul(e[j], Y[j][i]))

			XXDown[i] = group.Point().Add(XXDown[i],
				group.Point().Mul(e[j], XX[j][i]))
			YYDown[i] = group.Point().Add(YYDown[i],
				group.Point().Mul(e[j], YY[j][i]))
		}
	}

	return XXUp, YYUp, XXDown, YYDown
}
