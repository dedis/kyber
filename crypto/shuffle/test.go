package shuffle

import (
	"fmt"
	"time"
	"dissent/crypto"
)

func TestShuffle(suite crypto.Suite) {

	k := 100

	// Create a "server" private/public keypair
	h := suite.Secret().Pick(crypto.RandomStream)
	H := suite.Point().Mul(nil, h)

	// Create a set of ephemeral "client" keypairs to shuffle
	c := make([]crypto.Secret, k)
	C := make([]crypto.Point, k)
//	fmt.Println("\nclient keys:")
	for i := 0; i < k; i++ {
		c[i] = suite.Secret().Pick(crypto.RandomStream)
		C[i] = suite.Point().Mul(nil,c[i])
//		fmt.Println(" "+C[i].String())
	}

	// ElGamal-encrypt all these keypairs with the "server" key
	X := make([]crypto.Point, k)
	Y := make([]crypto.Point, k)
	r := suite.Secret()		// temporary
	for i := 0; i < k; i++ {
		r.Pick(crypto.RandomStream)
		X[i] = suite.Point().Mul(nil,r)
		Y[i] = suite.Point().Mul(H,r)	// ElGamal blinding factor
		Y[i].Add(Y[i],C[i])		// Encrypted client public key
	}

	// Do a key-shuffle
	fmt.Printf("%d-shuffle proof: ", k)
	pctx := newSigmaProver(suite, "PairShuffle")
	var ps PairShuffle
	ps.Init(suite, k)
	beg := time.Now()
	Xbar,Ybar := ps.Shuffle(nil,H,X,Y,crypto.RandomStream,pctx)
	end := time.Now()
	fmt.Printf("%f sec\n", (float64(end.Sub(beg)) / 1000000000.0))

	// Check it
	fmt.Printf("%d-shuffle verify: ", k)
	vctx := newSigmaVerifier(suite, "PairShuffle", pctx.Proof())
	beg = time.Now()
	if err := ps.Verify(nil,H,X,Y,Xbar,Ybar,vctx); err != nil {
		panic("Shuffle verify failed: "+err.Error())
	}
	end = time.Now()
	fmt.Printf("%f sec\n", (float64(end.Sub(beg)) / 1000000000.0))
}

func BenchShuffle(suite crypto.Suite) {
	TestShuffle(suite)
}

