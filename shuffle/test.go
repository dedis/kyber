package shuffle

import (
	//"fmt"
	//"encoding/hex"
	"github.com/dedis/crypto/abstract"
	"github.com/dedis/crypto/proof"
)

func TestShuffle(suite abstract.Suite, k int) {

	rand := suite.Cipher(abstract.RandomKey)

	// Create a "server" private/public keypair
	h := suite.Secret().Pick(rand)
	H := suite.Point().Mul(nil, h)

	// Create a set of ephemeral "client" keypairs to shuffle
	c := make([]abstract.Secret, k)
	C := make([]abstract.Point, k)
//	fmt.Println("\nclient keys:")
	for i := 0; i < k; i++ {
		c[i] = suite.Secret().Pick(rand)
		C[i] = suite.Point().Mul(nil,c[i])
//		fmt.Println(" "+C[i].String())
	}

	// ElGamal-encrypt all these keypairs with the "server" key
	X := make([]abstract.Point, k)
	Y := make([]abstract.Point, k)
	r := suite.Secret()		// temporary
	for i := 0; i < k; i++ {
		r.Pick(rand)
		X[i] = suite.Point().Mul(nil,r)
		Y[i] = suite.Point().Mul(H,r)	// ElGamal blinding factor
		Y[i].Add(Y[i],C[i])		// Encrypted client public key
	}

	// Do a key-shuffle
	Xbar,Ybar,prover := Shuffle(suite,nil,H,X,Y,rand)
	prf,err := proof.HashProve(suite,"PairShuffle",rand,prover)
	if err != nil {
		panic("Shuffle proof failed: "+err.Error())
	}
	//fmt.Printf("proof:\n%s\n",hex.Dump(prf))

	// Check it
	verifier := Verifier(suite,nil,H,X,Y,Xbar,Ybar)
	err = proof.HashVerify(suite,"PairShuffle",verifier,prf)
	if err != nil {
		panic("Shuffle verify failed: "+err.Error())
	}
}

