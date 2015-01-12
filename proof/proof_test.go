package proof

import (
	"fmt"
	"testing"
	"encoding/hex"
	"github.com/dedis/crypto/abstract"
	"github.com/dedis/crypto/random"
	"github.com/dedis/crypto/openssl"
)

func TestRep(t *testing.T) {
	suite := openssl.NewAES128SHA256P256()
	rand := random.Stream

	x := suite.Secret().Pick(rand)
	y := suite.Secret().Pick(rand)
	B := suite.Point().Base()
	X := suite.Point().Mul(nil,x)
	Y := suite.Point().Mul(X,y)
	R := suite.Point().Add(X,Y)

	choice := make(map[Predicate]int)

	// Simple single-secret predicate: prove X=x*B
	log := Rep("X","x","B")

	// Two-secret representation: prove R=x*B+y*X
	rep := Rep("R","x","B","y","X")

	// Make an and-predicate
	and := And(log,rep)
	andx := And(and)

	// Make up a couple incorrect facts
	falseLog := Rep("Y","x","B")
	falseRep := Rep("R","x","B","y","B")

	falseAnd := And(falseLog, falseRep)

	or1 := Or(falseAnd,andx)
	choice[or1] = 1
	or1x := Or(or1)				// test trivial case
	choice[or1x] = 0

	or2a := Rep("B","y","X")
	or2b := Rep("R","x","R")
	or2 := Or(or2a,or2b)
	or2x := Or(or2)				// test trivial case

	pred := Or(or1x,or2x)
	choice[pred] = 0

	sval := map[string]abstract.Secret{ "x":x, "y":y}
	pval := map[string]abstract.Point{ "B":B, "X":X, "Y":Y, "R":R}
	prover := pred.Prover(suite, sval, pval, choice)
	proof,err := HashProve(suite, "TEST", random.Stream, prover)
	if err != nil {
		panic("prover: "+err.Error())
	}

	verifier := pred.Verifier(suite, pval)
	if err := HashVerify(suite, "TEST", verifier, proof); err != nil {
		panic("verify: "+err.Error())
	}
}

// This code creates a simple discrete logarithm knowledge proof.
// In particular, that the prover knows a secret x
// that is the elliptic curve discrete logarithm of a point X
// with respect to some base B: i.e., X=x*B.
// If we take X as a public key and x as its corresponding private key,
// then this constitutes a "proof of ownership" of the public key X.
func ExampleRep_1() {
	pred := Rep("X","x","B")
	fmt.Println(pred.String())
	// Output: X=x*B
}

// This example shows how to generate and verify noninteractive proofs
// of the statement in the example above, i.e.,
// a proof of ownership of public key X.
func ExampleRep_2() {
	pred := Rep("X","x","B")
	fmt.Println(pred.String())

	// Crypto setup
	suite := openssl.NewAES128SHA256P256()
	rand := abstract.HashStream(suite, []byte("example"), nil)
	B := suite.Point().Base()		// standard base point

	// Create a public/private keypair (X,x)
	x := suite.Secret().Pick(rand)		// create a private key x
	X := suite.Point().Mul(nil,x)		// corresponding public key X

	// Generate a proof that we know the discrete logarithm of X.
	sval := map[string]abstract.Secret{"x":x}
	pval := map[string]abstract.Point{"B":B, "X":X}
	prover := pred.Prover(suite, sval, pval, nil)
	proof,_ := HashProve(suite, "TEST", rand, prover)
	fmt.Print("Proof:\n"+hex.Dump(proof))

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
	// 00000000  02 fd dc 29 56 ef d2 87  05 a6 af c2 c9 7d 6a 58  |...)V........}jX|
	// 00000010  74 96 a5 b2 10 82 2c 17  71 a4 43 db 37 14 42 48  |t.....,.q.C.7.BH|
	// 00000020  4a 94 d4 2f 53 b9 54 aa  c1 1c 8d d2 f0 af 89 72  |J../S.T........r|
	// 00000030  01 11 18 9a 44 15 13 63  e0 05 f8 84 71 ce e5 c7  |....D..c....q...|
	// 00000040  ed                                                |.|
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
	pred := Rep("X","x1","B1","x2","B2")
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
	pred := And(Rep("X","x","B"),Rep("Y","y","B"))
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
	pred := And(Rep("X1","x","B1"),Rep("X2","x","B2"))
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
	pred := Or(Rep("X","x","B"),Rep("Y","y","B"))
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
	pred := Or(Rep("X","x","B"),Rep("Y","y","B"))
	fmt.Println("Predicate: "+pred.String())

	// Crypto setup
	suite := openssl.NewAES128SHA256P256()
	rand := abstract.HashStream(suite, []byte("example"), nil)
	B := suite.Point().Base()		// standard base point

	// Create a public/private keypair (X,x) and a random point Y
	x := suite.Secret().Pick(rand)		// create a private key x
	X := suite.Point().Mul(nil,x)		// corresponding public key X
	Y,_ := suite.Point().Pick(nil,rand)	// pick a random point Y

	// We'll need to tell the prover which Or clause is actually true.
	// In this case clause 0, the first sub-predicate, is true:
	// i.e., we know a secret x such that X=x*B.
	choice := make(map[Predicate]int)
	choice[pred] = 0

	// Generate a proof that we know the discrete logarithm of X or Y.
	sval := map[string]abstract.Secret{"x":x}
	pval := map[string]abstract.Point{"B":B, "X":X, "Y":Y}
	prover := pred.Prover(suite, sval, pval, choice)
	proof,_ := HashProve(suite, "TEST", rand, prover)
	fmt.Print("Proof:\n"+hex.Dump(proof))

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
	// 00000000  02 f2 e1 15 37 a0 39 b3  f4 4c fb c2 ce 66 aa 51  |....7.9..L...f.Q|
	// 00000010  94 b5 f9 eb 78 2e fd fb  e3 10 9f bd 69 d4 8a c8  |....x.......i...|
	// 00000020  80 03 ba cf 9a 1c 3d e8  1e 53 3a 65 b3 e2 7a 24  |......=..S:e..z$|
	// 00000030  f8 06 6c d9 d9 30 30 8d  c8 53 e5 22 6a 0f a5 a8  |..l..00..S."j...|
	// 00000040  14 8d 9f 80 71 df 70 4b  35 50 21 28 71 6c ec c2  |....q.pK5P!(ql..|
	// 00000050  f4 ac b4 d6 0a d5 71 8a  de 47 51 fd e7 83 90 be  |......q..GQ.....|
	// 00000060  de d3 ac e3 87 21 a7 99  b2 d8 35 51 85 d1 2b 68  |.....!....5Q..+h|
	// 00000070  2a ae 85 ab 27 19 43 56  f0 49 7f ef 30 43 43 a7  |*...'.CV.I..0CC.|
	// 00000080  a7 ac 6a c9 df 17 5d 4b  08 71 0f c4 ec 1a 2a 43  |..j...]K.q....*C|
	// 00000090  f7 ef 5a c4 27 d1 24 36  81 77 00 80 76 f7 34 60  |..Z.'.$6.w..v.4`|
	// 000000a0  d7 c8 ca d1 3b 09 b8 54  67 1f 9a 7a 9c 7d e5 d9  |....;..Tg..z.}..|
	// 000000b0  81 5d 4e ee 55 57 dc a8  9c e6 39 d9 0e ad 37 5b  |.]N.UW....9...7[|
	// 000000c0  bc bd                                             |..|
	// Proof verified.
}

