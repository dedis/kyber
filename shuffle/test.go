package shuffle

import (
	//"fmt"
	//"time"
	"dissent/crypto"
	"dissent/crypto/proof"
	"dissent/crypto/random"
)

func TestShuffle(suite crypto.Suite, k int) {

	// Create a "server" private/public keypair
	h := suite.Secret().Pick(random.Stream)
	H := suite.Point().Mul(nil, h)

	// Create a set of ephemeral "client" keypairs to shuffle
	c := make([]crypto.Secret, k)
	C := make([]crypto.Point, k)
//	fmt.Println("\nclient keys:")
	for i := 0; i < k; i++ {
		c[i] = suite.Secret().Pick(random.Stream)
		C[i] = suite.Point().Mul(nil,c[i])
//		fmt.Println(" "+C[i].String())
	}

	// ElGamal-encrypt all these keypairs with the "server" key
	X := make([]crypto.Point, k)
	Y := make([]crypto.Point, k)
	r := suite.Secret()		// temporary
	for i := 0; i < k; i++ {
		r.Pick(random.Stream)
		X[i] = suite.Point().Mul(nil,r)
		Y[i] = suite.Point().Mul(H,r)	// ElGamal blinding factor
		Y[i].Add(Y[i],C[i])		// Encrypted client public key
	}

	// Do a key-shuffle
	Xbar,Ybar,prover := Shuffle(suite,nil,H,X,Y,random.Stream)
	prf,err := proof.HashProve(suite,"PairShuffle",random.Stream,prover)
	if err != nil {
		panic("Shuffle proof failed: "+err.Error())
	}

	// Check it
	verifier := Verifier(suite,nil,H,X,Y,Xbar,Ybar)
	err = proof.HashVerify(suite,"PairShuffle",verifier,prf)
	if err != nil {
		panic("Shuffle verify failed: "+err.Error())
	}
}

