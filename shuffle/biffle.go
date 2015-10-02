package shuffle

import (
	"github.com/dedis/crypto/abstract"
	"github.com/dedis/crypto/proof"
	"github.com/dedis/crypto/random"
)

func bifflePred() proof.Predicate {

	// Branch 0 of either/or proof (for bit=0)
	rep000 := proof.Rep("Xbar0-X0", "beta0", "G")
	rep001 := proof.Rep("Ybar0-Y0", "beta0", "H")
	rep010 := proof.Rep("Xbar1-X1", "beta1", "G")
	rep011 := proof.Rep("Ybar1-Y1", "beta1", "H")

	// Branch 1 of either/or proof (for bit=1)
	rep100 := proof.Rep("Xbar0-X1", "beta1", "G")
	rep101 := proof.Rep("Ybar0-Y1", "beta1", "H")
	rep110 := proof.Rep("Xbar1-X0", "beta0", "G")
	rep111 := proof.Rep("Ybar1-Y0", "beta0", "H")

	and0 := proof.And(rep000, rep001, rep010, rep011)
	and1 := proof.And(rep100, rep101, rep110, rep111)

	or := proof.Or(and0, and1)
	return or
}

func bifflePoints(suite abstract.Suite, G, H abstract.Point,
	X, Y, Xbar, Ybar [2]abstract.Point) map[string]abstract.Point {

	return map[string]abstract.Point{
		"G":        G,
		"H":        H,
		"Xbar0-X0": suite.Point().Sub(Xbar[0], X[0]),
		"Ybar0-Y0": suite.Point().Sub(Ybar[0], Y[0]),
		"Xbar1-X1": suite.Point().Sub(Xbar[1], X[1]),
		"Ybar1-Y1": suite.Point().Sub(Ybar[1], Y[1]),
		"Xbar0-X1": suite.Point().Sub(Xbar[0], X[1]),
		"Ybar0-Y1": suite.Point().Sub(Ybar[0], Y[1]),
		"Xbar1-X0": suite.Point().Sub(Xbar[1], X[0]),
		"Ybar1-Y0": suite.Point().Sub(Ybar[1], Y[0])}
}

// Binary shuffle ("biffle") for 2 ciphertexts based on general ZKPs.
func Biffle(suite abstract.Suite, G, H abstract.Point,
	X, Y [2]abstract.Point, rand abstract.Cipher) (
	Xbar, Ybar [2]abstract.Point, prover proof.Prover) {

	// Pick the single-bit permutation.
	bit := int(random.Byte(rand) & 1)

	// Pick a fresh ElGamal blinding factor for each pair
	var beta [2]abstract.Secret
	for i := 0; i < 2; i++ {
		beta[i] = suite.Secret().Pick(rand)
	}

	// Create the output pair vectors
	for i := 0; i < 2; i++ {
		pi_i := i ^ bit
		Xbar[i] = suite.Point().Mul(G, beta[pi_i])
		Xbar[i].Add(Xbar[i], X[pi_i])
		Ybar[i] = suite.Point().Mul(H, beta[pi_i])
		Ybar[i].Add(Ybar[i], Y[pi_i])
	}

	or := bifflePred()
	secrets := map[string]abstract.Secret{
		"beta0": beta[0],
		"beta1": beta[1]}
	points := bifflePoints(suite, G, H, X, Y, Xbar, Ybar)
	choice := map[proof.Predicate]int{or: bit}
	prover = or.Prover(suite, secrets, points, choice)
	return
}

func BiffleVerifier(suite abstract.Suite, G, H abstract.Point,
	X, Y, Xbar, Ybar [2]abstract.Point) (
	verifier proof.Verifier) {

	or := bifflePred()
	points := bifflePoints(suite, G, H, X, Y, Xbar, Ybar)
	return or.Verifier(suite, points)
}

func BiffleTest(suite abstract.Suite, N int) {

	rand := suite.Cipher(abstract.FreshKey)

	// Create a "server" private/public keypair
	h := suite.Secret().Pick(rand)
	H := suite.Point().BaseMul(h)

	// Create a set of ephemeral "client" keypairs to shuffle
	var c [2]abstract.Secret
	var C [2]abstract.Point
	//	fmt.Println("\nclient keys:")
	for i := 0; i < 2; i++ {
		c[i] = suite.Secret().Pick(rand)
		C[i] = suite.Point().BaseMul(c[i])
		//		fmt.Println(" "+C[i].String())
	}

	// ElGamal-encrypt all these keypairs with the "server" key
	var X, Y [2]abstract.Point
	r := suite.Secret() // temporary
	for i := 0; i < 2; i++ {
		r.Pick(rand)
		X[i] = suite.Point().BaseMul(r)
		Y[i] = suite.Point().Mul(H, r) // ElGamal blinding factor
		Y[i].Add(Y[i], C[i])           // Encrypted client public key
	}

	// Repeat only the actual shuffle portion for test purposes.
	for i := 0; i < N; i++ {

		// Do a key-shuffle
		Xbar, Ybar, prover := Biffle(suite, nil, H, X, Y, rand)
		prf, err := proof.HashProve(suite, "Biffle", rand, prover)
		if err != nil {
			panic("Biffle proof failed: " + err.Error())
		}
		//fmt.Printf("proof:\n%s\n",hex.Dump(prf))

		// Check it
		verifier := BiffleVerifier(suite, nil, H, X, Y, Xbar, Ybar)
		err = proof.HashVerify(suite, "Biffle", verifier, prf)
		if err != nil {
			panic("Biffle verify failed: " + err.Error())
		}
	}
}
