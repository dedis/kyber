package proof

import (
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/dedis/kyber"
	"github.com/dedis/kyber/group/edwards25519"
	"github.com/dedis/kyber/xof/blake2xb"
)

func TestRep(t *testing.T) {
	rand := blake2xb.New([]byte("seed"))
	suite := edwards25519.NewBlakeSHA256Ed25519WithRand(rand)

	x := suite.Scalar().Pick(rand)
	y := suite.Scalar().Pick(rand)
	B := suite.Point().Base()
	X := suite.Point().Mul(x, nil)
	Y := suite.Point().Mul(y, X)
	R := suite.Point().Add(X, Y)

	choice := make(map[Predicate]int)

	// Simple single-secret predicate: prove X=x*B
	log := Rep("X", "x", "B")

	// Two-secret representation: prove R=x*B+y*X
	rep := Rep("R", "x", "B", "y", "X")

	// Make an and-predicate
	and := And(log, rep)
	andx := And(and)

	// Make up a couple incorrect facts
	falseLog := Rep("Y", "x", "B")
	falseRep := Rep("R", "x", "B", "y", "B")

	falseAnd := And(falseLog, falseRep)

	or1 := Or(falseAnd, andx)
	choice[or1] = 1
	or1x := Or(or1) // test trivial case
	choice[or1x] = 0

	or2a := Rep("B", "y", "X")
	or2b := Rep("R", "x", "R")
	or2 := Or(or2a, or2b)
	or2x := Or(or2) // test trivial case

	pred := Or(or1x, or2x)
	choice[pred] = 0

	sval := map[string]kyber.Scalar{"x": x, "y": y}
	pval := map[string]kyber.Point{"B": B, "X": X, "Y": Y, "R": R}
	prover := pred.Prover(suite, sval, pval, choice)
	proof, err := HashProve(suite, "TEST", prover)
	if err != nil {
		t.Fatal("prover: " + err.Error())
	}

	verifier := pred.Verifier(suite, pval)
	if err := HashVerify(suite, "TEST", verifier, proof); err != nil {
		t.Fatal("verify: " + err.Error())
	}
}

// This code creates a simple discrete logarithm knowledge proof.
// In particular, that the prover knows a secret x
// that is the elliptic curve discrete logarithm of a point X
// with respect to some base B: i.e., X=x*B.
// If we take X as a public key and x as its corresponding private key,
// then this constitutes a "proof of ownership" of the public key X.
func Example_rep1() {
	pred := Rep("X", "x", "B")
	fmt.Println(pred.String())
	// Output: X=x*B
}

// This example shows how to generate and verify noninteractive proofs
// of the statement in the example above, i.e.,
// a proof of ownership of public key X.
func Example_rep2() {
	pred := Rep("X", "x", "B")
	fmt.Println(pred.String())

	// Crypto setup
	rand := blake2xb.New([]byte("example"))
	suite := edwards25519.NewBlakeSHA256Ed25519WithRand(rand)
	B := suite.Point().Base() // standard base point

	// Create a public/private keypair (X,x)
	x := suite.Scalar().Pick(rand) // create a private key x
	X := suite.Point().Mul(x, nil) // corresponding public key X

	// Generate a proof that we know the discrete logarithm of X.
	sval := map[string]kyber.Scalar{"x": x}
	pval := map[string]kyber.Point{"B": B, "X": X}
	prover := pred.Prover(suite, sval, pval, nil)
	proof, _ := HashProve(suite, "TEST", prover)
	fmt.Print("Proof:\n" + hex.Dump(proof))

	// Verify this knowledge proof.
	verifier := pred.Verifier(suite, pval)
	err := HashVerify(suite, "TEST", verifier, proof)
	if err != nil {
		fmt.Println("Proof failed to verify: ", err)
		return
	}
	fmt.Println("Proof verified.")

	// Output:
	// X=x*B
	// Proof:
	// 00000000  e9 a2 da f4 9d 7c e2 25  35 be 0a 15 78 9c ea ca  |.....|.%5...x...|
	// 00000010  a7 1e 6e d6 26 c3 40 ed  0d 3d 71 d4 a9 ef 55 3b  |..n.&.@..=q...U;|
	// 00000020  c1 84 20 a6 b7 79 86 9c  f8 dd 09 82 1e 48 a9 00  |.. ..y.......H..|
	// 00000030  3e f3 68 66 3f a0 58 f9  88 df b4 35 1b 2f 72 0d  |>.hf?.X....5./r.|
	// Proof verified.
}

// This code creates a predicate stating that the prover knows a representation
// of point X with respect to two different bases B1 and B2.
// This means the prover knows two secrets x1 and x2
// such that X=x1*B1+x2*B2.
//
// Point X might constitute a Pedersen commitment, for example,
// where x1 is the value being committed to and x2 is a random blinding factor.
// Assuming the discrete logarithm problem is hard in the relevant group
// and the logarithmic relationship between bases B1 and B2 is unknown -
// which we would be true if B1 and B2 are chosen at random, for example -
// then a prover who has committed to point P
// will later be unable to "open" the commitment
// using anything other than secrets x1 and x2.
// The prover can also prove that one of the secrets (say x1)
// is equal to a secret used in the representation of some other point,
// while leaving the other secret (x2) unconstrained.
//
// If the prover does know the relationship between B1 and B2, however,
// then X does not serve as a useful commitment:
// the prover can trivially compute the x1 corresponding to an arbitrary x2.
//
func Example_rep3() {
	pred := Rep("X", "x1", "B1", "x2", "B2")
	fmt.Println(pred.String())
	// Output: X=x1*B1+x2*B2
}

// This code creates an And predicate indicating that
// the prover knows two different secrets x and y,
// such that point X is equal to x*B
// and point Y is equal to y*B.
// This predicate might be used to prove knowledge of
// the private keys corresponding to two public keys X and Y, for example.
func Example_and1() {
	pred := And(Rep("X", "x", "B"), Rep("Y", "y", "B"))
	fmt.Println(pred.String())
	// Output: X=x*B && Y=y*B
}

// This code creates an And predicate indicating that
// the prover knows a single secret value x,
// such that point X1 is equal to x*B1
// and point X2 is equal to x*B2.
// Thus, the prover not only proves knowledge of the discrete logarithm
// of X1 with respect to B1 and of X2 with respect to B2,
// but also proves that those two discrete logarithms are equal.
func Example_and2() {
	pred := And(Rep("X1", "x", "B1"), Rep("X2", "x", "B2"))
	fmt.Println(pred.String())
	// Output: X1=x*B1 && X2=x*B2
}

// This code creates an Or predicate indicating that
// the prover either knows a secret x such that X=x*B,
// or the prover knows a secret y such that Y=y*B.
// This predicate in essence proves knowledge of the private key
// for one of two public keys X or Y,
// without revealing which key the prover owns.
func Example_or1() {
	pred := Or(Rep("X", "x", "B"), Rep("Y", "y", "B"))
	fmt.Println(pred.String())
	// Output: X=x*B || Y=y*B
}

// This code shows how to create and verify Or-predicate proofs,
// such as the one above.
// In this case, we know a secret x such that X=x*B,
// but we don't know a secret y such that Y=y*B,
// because we simply pick Y as a random point
// instead of generating it by scalar multiplication.
// (And if the group is cryptographically secure
// we won't find be able to find such a y.)
func Example_or2() {
	// Create an Or predicate.
	pred := Or(Rep("X", "x", "B"), Rep("Y", "y", "B"))
	fmt.Println("Predicate: " + pred.String())

	// Crypto setup
	rand := blake2xb.New([]byte("example"))
	suite := edwards25519.NewBlakeSHA256Ed25519WithRand(rand)
	B := suite.Point().Base() // standard base point

	// Create a public/private keypair (X,x) and a random point Y
	x := suite.Scalar().Pick(rand) // create a private key x
	X := suite.Point().Mul(x, nil) // corresponding public key X
	Y := suite.Point().Pick(rand)  // pick a random point Y

	// We'll need to tell the prover which Or clause is actually true.
	// In this case clause 0, the first sub-predicate, is true:
	// i.e., we know a secret x such that X=x*B.
	choice := make(map[Predicate]int)
	choice[pred] = 0

	// Generate a proof that we know the discrete logarithm of X or Y.
	sval := map[string]kyber.Scalar{"x": x}
	pval := map[string]kyber.Point{"B": B, "X": X, "Y": Y}
	prover := pred.Prover(suite, sval, pval, choice)
	proof, _ := HashProve(suite, "TEST", prover)
	fmt.Print("Proof:\n" + hex.Dump(proof))

	// Verify this knowledge proof.
	// The verifier doesn't need the secret values or choice map, of course.
	verifier := pred.Verifier(suite, pval)
	err := HashVerify(suite, "TEST", verifier, proof)
	if err != nil {
		fmt.Println("Proof failed to verify: " + err.Error())
	}
	fmt.Println("Proof verified.")

	// Output:
	// Predicate: X=x*B || Y=y*B
	// Proof:
	// 00000000  44 bb 0f bb 2b 06 29 a6  73 59 0f c1 5a ca de 36  |D...+.).sY..Z..6|
	// 00000010  4c c8 15 ed b1 eb 50 d3  d9 d2 9b 31 6c d3 0f 6b  |L.....P....1l..k|
	// 00000020  a2 a9 bc d2 8c 6d d0 5e  9a 8e d1 8e 04 fb 88 af  |.....m.^........|
	// 00000030  fb 90 8a 2a 71 ac 34 08  f9 bc 07 78 08 44 40 07  |...*q.4....x.D@.|
	// 00000040  ab 1f 36 7e 7b db 50 7d  49 38 34 75 69 07 67 4b  |..6~{.P}I84ui.gK|
	// 00000050  55 cb 28 f2 50 ad d1 4b  24 d2 d1 44 fe 44 b0 0e  |U.(.P..K$..D.D..|
	// 00000060  00 e8 d3 8b 37 76 4f 47  d1 4a 93 0c cd df 20 08  |....7vOG.J.... .|
	// 00000070  fc 0f ad f9 01 6c 30 c0  02 d4 fa 1b 1f 1c fa 04  |.....l0.........|
	// 00000080  6d 2a a7 d8 8e 67 72 87  51 0e 16 72 51 87 99 83  |m*...gr.Q..rQ...|
	// 00000090  2e c9 4e a1 ca 20 7d 64  33 04 f5 66 9b d3 74 03  |..N.. }d3..f..t.|
	// 000000a0  2b e0 be 8d 56 55 1a d1  6e 11 21 fc 20 3e 0f 5f  |+...VU..n.!. >._|
	// 000000b0  4d 97 a9 bf 1a 28 27 6d  3b 71 04 e1 c0 86 96 08  |M....('m;q......|
	// Proof verified.
}
