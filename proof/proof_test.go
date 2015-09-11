package proof

import (
	"encoding/hex"
	"fmt"
	"github.com/dedis/crypto/abstract"
	"github.com/dedis/crypto/openssl"
	"testing"
)

func TestRep(t *testing.T) {
	suite := openssl.NewAES128SHA256P256()
	rand := suite.Cipher(abstract.RandomKey)

	x := suite.Secret().Pick(rand)
	y := suite.Secret().Pick(rand)
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

	sval := map[string]abstract.Secret{"x": x, "y": y}
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
	suite := openssl.NewAES128SHA256P256()
	rand := suite.Cipher([]byte("example"))
	B := suite.Point().Base() // standard base point

	// Create a public/private keypair (X,x)
	x := suite.Secret().Pick(rand) // create a private key x
	X := suite.Point().BaseMul(x) // corresponding public key X

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
	// 00000000  02 23 62 b1 f9 cb f4 a2  6d 7f 3e 69 cb b6 77 ab  |.#b.....m.>i..w.|
	// 00000010  90 fc 7c db a0 c6 e8 12  f2 0a d4 40 a4 b6 c4 de  |..|........@....|
	// 00000020  9e 53 67 12 c7 31 0a 92  ed 76 c4 4d 2c 4b fc 2c  |.Sg..1...v.M,K.,|
	// 00000030  56 db 2d 8a 84 ec 5d e5  31 17 80 76 a8 ea 46 04  |V.-...].1..v..F.|
	// 00000040  c8                                                |.|
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
	rand := suite.Cipher([]byte("example"))
	B := suite.Point().Base() // standard base point

	// Create a public/private keypair (X,x) and a random point Y
	x := suite.Secret().Pick(rand)        // create a private key x
	X := suite.Point().BaseMul(x)        // corresponding public key X
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
	// 00000000  02 af 84 ed e5 86 04 cf  81 e4 18 17 84 0c 39 ab  |..............9.|
	// 00000010  fe 5c bc cc 00 85 e0 a2  ee aa d5 22 18 dd c4 a1  |.\........."....|
	// 00000020  5b 03 df 9c 59 21 0e 1c  44 99 23 a1 54 92 21 c9  |[...Y!..D.#.T.!.|
	// 00000030  d6 b3 84 85 ad 87 dd a3  64 c0 b9 eb 4d 92 5b cb  |........d...M.[.|
	// 00000040  c6 4f e7 67 95 36 6a e4  e7 ca b5 14 b7 99 16 60  |.O.g.6j........`|
	// 00000050  71 91 ad b0 f1 86 43 df  6a 45 1f cb a2 93 7e b3  |q.....C.jE....~.|
	// 00000060  b5 7b 32 17 7d 53 c5 e4  48 79 49 b2 3e 1e e2 62  |.{2.}S..HyI.>..b|
	// 00000070  39 08 13 d5 2e f8 c5 e9  c1 28 09 91 7a 95 c9 12  |9........(..z...|
	// 00000080  17 85 f5 eb 2d 8e 6b 37  3a b5 ff 45 25 e7 0c aa  |....-.k7:..E%...|
	// 00000090  94 43 cf 67 52 2e 1d 2c  1b a4 c0 ca 96 d6 03 08  |.C.gR..,........|
	// 000000a0  c0 0d 93 8b c6 f6 34 12  83 a0 32 2e 82 2c 4b fb  |......4...2..,K.|
	// 000000b0  b3 0c a1 4b a5 e3 27 43  b6 2f ed fa ca 4f 93 83  |...K..'C./...O..|
	// 000000c0  fd 56                                             |.V|
	// Proof verified.
}
