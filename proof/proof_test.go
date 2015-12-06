package proof

import (
	"encoding/hex"
	"fmt"
	"github.com/dedis/crypto/abstract"
	"github.com/dedis/crypto/suite"
	"testing"
)

func TestRep(t *testing.T) {
	suite := suite.Default(nil)
	rand := suite.Cipher(abstract.FreshKey)

	x := suite.Scalar().Random(rand)
	y := suite.Scalar().Random(rand)
	B := suite.Point().Base()
	X := suite.Point().BaseMul(x)
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

	sval := map[string]abstract.Scalar{"x": x, "y": y}
	pval := map[string]abstract.Point{"B": B, "X": X, "Y": Y, "R": R}
	prover := pred.Prover(suite, sval, pval, choice)
	proof, err := HashProve(suite, "TEST", rand, prover)
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
	suite := suite.Default(nil)
	rand := suite.Cipher([]byte("example"))
	B := suite.Point().Base() // standard base point

	// Create a public/private keypair (X,x)
	x := suite.Scalar().Random(rand) // create a private key x
	X := suite.Point().BaseMul(x)    // corresponding public key X

	// Generate a proof that we know the discrete logarithm of X.
	sval := map[string]abstract.Scalar{"x": x}
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
	// 00000000  80 63 15 19 7f 91 5f 81  94 40 3b a0 7b cd b2 53  |.c...._..@;.{..S|
	// 00000010  39 e6 09 e8 dd 6b 33 9a  4a fa cc 6b b5 aa ef 52  |9....k3.J..k...R|
	// 00000020  0a af 3e f6 39 5e a4 7f  60 b5 15 ac 10 82 1c ee  |..>.9^..`.......|
	// 00000030  9f 70 7a e1 2a 7e 20 c3  ad 9a 8b b7 f2 6e 30 ae  |.pz.*~ ......n0.|
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
	suite := suite.Default(nil)
	rand := suite.Cipher([]byte("example"))
	B := suite.Point().Base() // standard base point

	// Create a public/private keypair (X,x) and a random point Y
	x := suite.Scalar().Random(rand) // create a private key x
	X := suite.Point().BaseMul(x)    // corresponding public key X
	Y := suite.Point().Random(rand)  // pick a random point Y

	// We'll need to tell the prover which Or clause is actually true.
	// In this case clause 0, the first sub-predicate, is true:
	// i.e., we know a secret x such that X=x*B.
	choice := make(map[Predicate]int)
	choice[pred] = 0

	// Generate a proof that we know the discrete logarithm of X or Y.
	sval := map[string]abstract.Scalar{"x": x}
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
	// 00000000  62 22 5e ef 5a 93 60 f2  d8 f8 87 41 06 53 33 e9  |b"^.Z.`....A.S3.|
	// 00000010  68 20 ea 1b 5d 7b 0d de  5f 2c 0c 76 cd ce 57 85  |h ..]{.._,.v..W.|
	// 00000020  20 d4 30 9b 06 5b dd f1  3d d6 be 3c ab b7 bf f8  | .0..[..=..<....|
	// 00000030  9a 4e 73 0e 01 eb c8 6c  1e 8c 52 64 6a 6b 7d cd  |.Ns....l..Rdjk}.|
	// 00000040  0f 61 a8 44 7b 3b bc 42  c7 e3 6e 41 12 b3 7d 3f  |.a.D{;.B..nA..}?|
	// 00000050  d5 97 3c 29 1b d8 8d b2  9c 25 78 db 9a c3 0d 19  |..<).....%x.....|
	// 00000060  00 78 6c ff 40 ae 0b 42  60 b5 7f 1e 23 1b 26 98  |.xl.@..B`...#.&.|
	// 00000070  54 bc bb 6d ff 68 2b f4  77 7c 4f 22 a3 3a 82 63  |T..m.h+.w|O".:.c|
	// 00000080  03 1e 0d 24 1e e7 bc 9b  7b f0 d5 5d 43 e0 31 1b  |...$....{..]C.1.|
	// 00000090  80 c4 94 41 d6 85 e0 85  ec 3d 40 d6 bf 75 d8 e8  |...A.....=@..u..|
	// 000000a0  00 dc 00 fb a1 ff d8 63  80 5d b0 0a 2f b6 0d 55  |.......c.]../..U|
	// 000000b0  bd 0e 81 bb fb 4f ce 76  3b 6f 94 b8 a5 90 f5 43  |.....O.v;o.....C|
	// Proof verified.
}
