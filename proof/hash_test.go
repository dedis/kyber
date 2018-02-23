package proof

import (
	"encoding/hex"
	"fmt"

	"github.com/dedis/kyber"
	"github.com/dedis/kyber/group/edwards25519"
	"github.com/dedis/kyber/xof/blake2xb"
)

// This example shows how to build classic ElGamal-style digital signatures
// using the Camenisch/Stadler proof framework and HashProver.
func Example_hashProve1() {

	// Crypto setup
	rand := blake2xb.New([]byte("example"))
	suite := edwards25519.NewBlakeSHA256Ed25519WithRand(rand)
	B := suite.Point().Base() // standard base point

	// Create a public/private keypair (X,x)
	x := suite.Scalar().Pick(suite.RandomStream()) // create a private key x
	X := suite.Point().Mul(x, nil)                 // corresponding public key X

	// Generate a proof that we know the discrete logarithm of X.
	M := "Hello World!" // message we want to sign
	rep := Rep("X", "x", "B")
	sec := map[string]kyber.Scalar{"x": x}
	pub := map[string]kyber.Point{"B": B, "X": X}
	prover := rep.Prover(suite, sec, pub, nil)
	proof, _ := HashProve(suite, M, prover)
	fmt.Print("Signature:\n" + hex.Dump(proof))

	// Verify the signature against the correct message M.
	verifier := rep.Verifier(suite, pub)
	err := HashVerify(suite, M, verifier, proof)
	if err != nil {
		fmt.Println("signature failed to verify: ", err)
		return
	}
	fmt.Println("Signature verified against correct message M.")

	// Now verify the signature against the WRONG message.
	BAD := "Goodbye World!"
	verifier = rep.Verifier(suite, pub)
	err = HashVerify(suite, BAD, verifier, proof)
	fmt.Println("Signature verify against wrong message: " + err.Error())

	// Output:
	// Signature:
	// 00000000  e9 a2 da f4 9d 7c e2 25  35 be 0a 15 78 9c ea ca  |.....|.%5...x...|
	// 00000010  a7 1e 6e d6 26 c3 40 ed  0d 3d 71 d4 a9 ef 55 3b  |..n.&.@..=q...U;|
	// 00000020  64 76 55 7b 3c 63 20 d8  4b 29 3a 1c 7f 44 59 ad  |dvU{<c .K):..DY.|
	// 00000030  ff 5d c1 ff 06 1d 97 0c  59 06 3c 4b aa 7b 7c 0c  |.]......Y.<K.{|.|
	// Signature verified against correct message M.
	// Signature verify against wrong message: invalid proof: commit mismatch
}

// This example implements Linkable Ring Signatures (LRS) generically
// using the Camenisch/Stadler proof framework and HashProver.
//
// A ring signature proves that the signer owns one of a list of public keys,
// without revealing anything about which public key the signer actually owns.
// A linkable ring signature (LRS) is the same but includes a linkage tag,
// which the signer proves to correspond 1-to-1 with the signer's key,
// but whose relationship to the private key remains secret
// from anyone who does not hold the private key.
// A key-holder who signs multiple messages in the same public "linkage scope"
// will be forced to use the same linkage tag in each such signature,
// enabling others to tell whether two signatures in a given scope
// were produced by the same or different signers.
//
// This scheme is conceptually similar to that of Liu/Wei/Wong in
// "Linkable and Anonymous Signature for Ad Hoc Groups".
// This example implementation is less space-efficient, however,
// because it uses the generic HashProver for Fiat-Shamir noninteractivity
// instead of Liu/Wei/Wong's customized hash-ring structure.
//
func Example_hashProve2() {

	// Crypto setup
	rand := blake2xb.New([]byte("example"))
	suite := edwards25519.NewBlakeSHA256Ed25519WithRand(rand)
	B := suite.Point().Base() // standard base point

	// Create an anonymity ring of random "public keys"
	X := make([]kyber.Point, 3)
	for i := range X { // pick random points
		X[i] = suite.Point().Pick(suite.RandomStream())
	}

	// Make just one of them an actual public/private keypair (X[mine],x)
	mine := 2                                      // only the signer knows this
	x := suite.Scalar().Pick(suite.RandomStream()) // create a private key x
	X[mine] = suite.Point().Mul(x, nil)            // corresponding public key X

	// Produce the correct linkage tag for the signature,
	// as a pseudorandom base point multiplied by our private key.
	linkScope := []byte("The Linkage Scope")
	linkHash := suite.XOF(linkScope)
	linkBase := suite.Point().Pick(linkHash)
	linkTag := suite.Point().Mul(x, linkBase)

	// Generate the proof predicate: an OR branch for each public key.
	sec := map[string]kyber.Scalar{"x": x}
	pub := map[string]kyber.Point{"B": B, "BT": linkBase, "T": linkTag}
	preds := make([]Predicate, len(X))
	for i := range X {
		name := fmt.Sprintf("X[%d]", i) // "X[0]","X[1]",...
		pub[name] = X[i]                // public point value

		// Predicate indicates knowledge of the private key for X[i]
		// and correspondence of the key with the linkage tag
		preds[i] = And(Rep(name, "x", "B"), Rep("T", "x", "BT"))
	}
	pred := Or(preds...) // make a big Or predicate
	fmt.Printf("Linkable Ring Signature Predicate:\n%s\n", pred.String())

	// The prover needs to know which Or branch (mine) is actually true.
	choice := make(map[Predicate]int)
	choice[pred] = mine

	// Generate the signature
	M := "Hello World!" // message we want to sign
	prover := pred.Prover(suite, sec, pub, choice)
	proof, _ := HashProve(suite, M, prover)
	fmt.Print("Linkable Ring Signature:\n" + hex.Dump(proof))

	// Verify the signature
	verifier := pred.Verifier(suite, pub)
	err := HashVerify(suite, M, verifier, proof)
	if err != nil {
		fmt.Println("signature failed to verify: ", err)
		return
	}
	fmt.Println("Linkable Ring Signature verified.")

	// Output:
	// Linkable Ring Signature Predicate:
	// (X[0]=x*B && T=x*BT) || (X[1]=x*B && T=x*BT) || (X[2]=x*B && T=x*BT)
	// Linkable Ring Signature:
	// 00000000  d6 73 58 df 19 52 fc a7  70 2b 42 00 83 03 bd 5f  |.sX..R..p+B...._|
	// 00000010  4d 86 4b 8d db 3d 76 17  00 17 2c b9 a3 6b 54 57  |M.K..=v...,..kTW|
	// 00000020  e1 fd c0 d4 00 9b ea 5d  85 2b f1 83 41 80 ec 83  |.......].+..A...|
	// 00000030  ac b2 f4 0c e4 01 35 61  34 ef 94 34 0b 77 44 3e  |......5a4..4.wD>|
	// 00000040  e3 bd 92 b2 f8 f5 85 97  c4 dd 39 f7 a0 b6 ef b1  |..........9.....|
	// 00000050  65 c6 53 80 e4 78 07 52  62 a5 0b a5 f1 0b 33 2b  |e.S..x.Rb.....3+|
	// 00000060  c8 f5 43 9b 1c bf c2 1a  4a 5b ea b0 e9 18 d1 db  |..C.....J[......|
	// 00000070  a3 57 eb e0 5b d4 99 0e  af f2 10 d4 29 a9 0e 43  |.W..[.......)..C|
	// 00000080  fd 20 a1 42 01 ef 68 a0  43 64 70 f4 f9 09 0f 77  |. .B..h.Cdp....w|
	// 00000090  b3 b0 82 0a 31 8a 66 41  a8 d0 f4 5f 1e da 6e 63  |....1.fA..._..nc|
	// 000000a0  a0 46 74 75 86 6f 3e 85  52 f0 74 6c 74 3b 00 1b  |.Ftu.o>.R.tlt;..|
	// 000000b0  b2 4b 93 95 33 1d 9e 6a  96 43 e5 e2 30 46 6e e5  |.K..3..j.C..0Fn.|
	// 000000c0  2b e0 be 8d 56 55 1a d1  6e 11 21 fc 20 3e 0f 5f  |+...VU..n.!. >._|
	// 000000d0  4d 97 a9 bf 1a 28 27 6d  3b 71 04 e1 c0 86 96 08  |M....('m;q......|
	// 000000e0  8d 0e c0 14 e3 eb 8b e9  16 40 29 60 ab bd e6 1a  |.........@)`....|
	// 000000f0  68 54 5e 29 c8 85 05 bc  4a 27 83 d9 32 cc 74 0f  |hT^)....J'..2.t.|
	// 00000100  5e 16 30 25 e2 d6 35 2a  d4 3e b5 07 1f d4 0a eb  |^.0%..5*.>......|
	// 00000110  5d ef 3b 84 35 39 90 0c  3a 02 bb ee c7 9a e7 09  |].;.59..:.......|
	// 00000120  d1 cc 1e e1 f4 3b 88 52  e5 99 ed 50 d7 66 b5 76  |.....;.R...P.f.v|
	// 00000130  59 6c c1 66 98 07 e5 73  e7 b8 fe 48 43 a0 74 09  |Yl.f...s...HC.t.|
	// 00000140  84 9a 7b ec 21 aa ff c7  fc 79 c6 8f f4 23 82 e7  |..{.!....y...#..|
	// 00000150  d3 71 69 20 d6 94 27 ef  11 0b 4c a5 79 54 1f 09  |.qi ..'...L.yT..|
	// 00000160  6b ec 50 c2 1f 98 38 ea  a7 02 da ca aa 1b 6b 39  |k.P...8.......k9|
	// 00000170  70 b8 35 6c fe 03 1f b0  08 42 e0 5d b2 5e 40 04  |p.5l.....B.].^@.|
	// Linkable Ring Signature verified.
}
