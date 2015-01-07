package proof

import (
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/dedis/crypto/abstract"
	"github.com/dedis/crypto/openssl"
	"github.com/dedis/crypto/random"
)

func TestRep(t *testing.T) {
	suite := openssl.NewAES128SHA256P256()
	rand := random.Stream

	x := suite.Secret().Pick(rand)
	y := suite.Secret().Pick(rand)
	B := suite.Point().Base()
	X := suite.Point().Mul(nil, x)
	Y := suite.Point().Mul(X, y)
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

	sval := map[string]abstract.Secret{"x": x, "y": y}
	pval := map[string]abstract.Point{"B": B, "X": X, "Y": Y, "R": R}
	prover := pred.Prover(suite, sval, pval, choice)
	proof, err := HashProve(suite, "TEST", random.Stream, prover)
	if err != nil {
		panic("prover: " + err.Error())
	}

	verifier := pred.Verifier(suite, pval)
	if err := HashVerify(suite, "TEST", verifier, proof); err != nil {
		panic("verify: " + err.Error())
	}
}

// This code creates a simple discrete logarithm knowledge proof.
// In particular, that the prover knows a secret x
// that is the elliptic curve discrete logarithm of a point X
// with respect to some base B: i.e., X=x*B.
// If we take X as a public key and x as its corresponding private key,
// then this constitutes a "proof of ownership" of the public key X.
func ExampleRep_1() {
	pred := Rep("X", "x", "B")
	fmt.Println(pred.String())
	// Output: X=x*B
}

// This example shows how to generate and verify noninteractive proofs
// of the statement in the example above, i.e.,
// a proof of ownership of public key X.
func ExampleRep_2() {
	pred := Rep("X", "x", "B")
	fmt.Println(pred.String())

	// Crypto setup
	suite := openssl.NewAES128SHA256P256()
	rand := abstract.HashStream(suite, []byte("example"), nil)
	B := suite.Point().Base() // standard base point

	// Create a public/private keypair (X,x)
	x := suite.Secret().Pick(rand) // create a private key x
	X := suite.Point().Mul(nil, x) // corresponding public key X

	// Generate a proof that we know the discrete logarithm of X.
	sval := map[string]abstract.Secret{"x": x}
	pval := map[string]abstract.Point{"B": B, "X": X}
	prover := pred.Prover(suite, sval, pval, nil)
	proof, _ := HashProve(suite, "TEST", rand, prover)
	fmt.Print("Proof:\n" + hex.Dump(proof))

	// Verify this knowledge proof.
	verifier := pred.Verifier(suite, pval)
	err := HashVerify(suite, "TEST", verifier, proof)
	if err != nil {
		panic("proof failed to verify!")
	}
	fmt.Println("Proof verified.")

	// Output:
	// X=x*B
	// Proof:
	// 00000000  02 a7 88 0a 50 7e 71 48  03 0d a8 6c 31 f7 01 ed  |....P~qH...l1...|
	// 00000010  c5 ea 92 5a b3 35 85 42  43 ec b2 72 1c 50 10 88  |...Z.5.BC..r.P..|
	// 00000020  fe a7 af 11 48 58 58 90  76 2e c9 67 c6 6a 85 94  |....HXX.v..g.j..|
	// 00000030  02 ad 5e b5 e6 26 b9 63  8b 85 b8 24 c6 60 19 80  |..^..&.c...$.`..|
	// 00000040  00                                                |.|
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
func ExampleRep_3() {
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
func ExampleAnd_1() {
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
func ExampleAnd_2() {
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
func ExampleOr_1() {
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
func ExampleOr_2() {
	// Create an Or predicate.
	pred := Or(Rep("X", "x", "B"), Rep("Y", "y", "B"))
	fmt.Println("Predicate: " + pred.String())

	// Crypto setup
	suite := openssl.NewAES128SHA256P256()
	rand := abstract.HashStream(suite, []byte("example"), nil)
	B := suite.Point().Base() // standard base point

	// Create a public/private keypair (X,x) and a random point Y
	x := suite.Secret().Pick(rand)        // create a private key x
	X := suite.Point().Mul(nil, x)        // corresponding public key X
	Y, _ := suite.Point().Pick(nil, rand) // pick a random point Y

	// We'll need to tell the prover which Or clause is actually true.
	// In this case clause 0, the first sub-predicate, is true:
	// i.e., we know a secret x such that X=x*B.
	choice := make(map[Predicate]int)
	choice[pred] = 0

	// Generate a proof that we know the discrete logarithm of X or Y.
	sval := map[string]abstract.Secret{"x": x}
	pval := map[string]abstract.Point{"B": B, "X": X, "Y": Y}
	prover := pred.Prover(suite, sval, pval, choice)
	proof, _ := HashProve(suite, "TEST", rand, prover)
	fmt.Print("Proof:\n" + hex.Dump(proof))

	// Verify this knowledge proof.
	// The verifier doesn't need the secret values or choice map, of course.
	verifier := pred.Verifier(suite, pval)
	err := HashVerify(suite, "TEST", verifier, proof)
	if err != nil {
		panic("proof failed to verify!")
	}
	fmt.Println("Proof verified.")

	// Output:
	// Predicate: X=x*B || Y=y*B
	// Proof:
	// 00000000  03 07 21 da 6b 4c ea f2  87 4a bf 97 e2 66 bc cf  |..!.kL...J...f..|
	// 00000010  bd d3 f1 f9 5b bc 5b 76  0d 7f 73 d9 9a 6d cb 32  |....[.[v..s..m.2|
	// 00000020  c7 03 70 67 8a e2 39 52  e7 a9 ce 14 d7 a4 19 01  |..pg..9R........|
	// 00000030  f7 35 fd 1e a1 5c 06 12  71 39 ad c9 f0 50 b7 cd  |.5...\..q9...P..|
	// 00000040  5e 86 5c f3 70 d6 e9 48  53 84 2a b7 31 1a 60 b1  |^.\.p..HS.*.1.`.|
	// 00000050  07 73 c8 93 d6 07 64 c2  b8 12 3e b6 05 ef f0 3c  |.s....d...>....<|
	// 00000060  04 44 0e d5 2c 26 21 a1  16 75 02 30 b5 fb 04 5e  |.D..,&!..u.0...^|
	// 00000070  0e cd 89 2a 95 f8 cd 5e  ec 1c 36 b5 a6 82 e5 70  |...*...^..6....p|
	// 00000080  97 0a af c2 54 4e 1c a8  51 ef 48 52 bf 8e a4 b7  |....TN..Q.HR....|
	// 00000090  6b 34 aa 05 7c 8f 3e ac  4b b7 8c f6 55 44 31 9d  |k4..|.>.K...UD1.|
	// 000000a0  56 5b 02 51 73 a0 bc 3e  2d a9 66 78 17 50 c4 c9  |V[.Qs..>-.fx.P..|
	// 000000b0  2b 6a d2 77 cd 9b 2b e0  df a1 48 ab b4 df c6 ed  |+j.w..+...H.....|
	// 000000c0  2e 3e                                             |.>|
	// Proof verified.
}
