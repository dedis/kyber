package shuffle

import (
	//"fmt"
	//"encoding/hex"
	"github.com/dedis/crypto/abstract"
	"github.com/dedis/crypto/proof"
)

func TestShuffle(suite abstract.Suite, k int, N int) {

	rand := suite.Cipher(abstract.FreshKey)

	// Create a "server" private/public keypair
	h := suite.Scalar().Random(rand)
	H := suite.Point().BaseMul(h)

	// Create a set of ephemeral "client" keypairs to shuffle
	c := make([]abstract.Scalar, k)
	C := make([]abstract.Point, k)
	//	fmt.Println("\nclient keys:")
	for i := 0; i < k; i++ {
		c[i] = suite.Scalar().Random(rand)
		C[i] = suite.Point().BaseMul(c[i])
		//		fmt.Println(" "+C[i].String())
	}

	// ElGamal-encrypt all these keypairs with the "server" key
	X := make([]abstract.Point, k)
	Y := make([]abstract.Point, k)
	r := suite.Scalar() // temporary
	for i := 0; i < k; i++ {
		r.Random(rand)
		X[i] = suite.Point().BaseMul(r)
		Y[i] = suite.Point().Mul(H, r) // ElGamal blinding factor
		Y[i].Add(Y[i], C[i])           // Encrypted client public key
	}

	// Repeat only the actual shuffle portion for test purposes.
	for i := 0; i < N; i++ {

		// Do a key-shuffle
		nilPoint := abstract.Point{nil}
		Xbar, Ybar, prover := Shuffle(suite, nilPoint, H, X, Y, rand)
		prf, err := proof.HashProve(suite, "PairShuffle", rand, prover)
		if err != nil {
			panic("Shuffle proof failed: " + err.Error())
		}
		//fmt.Printf("proof:\n%s\n",hex.Dump(prf))

		// Check it
		verifier := Verifier(suite, nilPoint, H, X, Y, Xbar, Ybar)
		err = proof.HashVerify(suite, "PairShuffle", verifier, prf)
		if err != nil {
			panic("Shuffle verify failed: " + err.Error())
		}
	}
}
