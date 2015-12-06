package proof

import (
	"encoding/hex"
	"fmt"
	"github.com/dedis/crypto/abstract"
	"github.com/dedis/crypto/suite"
)

// This example shows how to build classic ElGamal-style digital signatures
// using the Camenisch/Stadler proof framework and HashProver.
func ExampleHashProve_1() {

	// Crypto setup
	suite := suite.Default(nil)
	rand := suite.Cipher([]byte("example"))
	B := suite.Point().Base() // standard base point

	// Create a public/private keypair (X,x)
	x := suite.Scalar().Random(rand) // create a private key x
	X := suite.Point().BaseMul(x)    // corresponding public key X

	// Generate a proof that we know the discrete logarithm of X.
	M := "Hello World!" // message we want to sign
	rep := Rep("X", "x", "B")
	sec := map[string]abstract.Scalar{"x": x}
	pub := map[string]abstract.Point{"B": B, "X": X}
	prover := rep.Prover(suite, sec, pub, nil)
	proof, _ := HashProve(suite, M, rand, prover)
	fmt.Print("Signature:\n" + hex.Dump(proof))

	// Verify the signature against the correct message M.
	verifier := rep.Verifier(suite, pub)
	err := HashVerify(suite, M, verifier, proof)
	if err != nil {
		panic("signature failed to verify!")
	}
	fmt.Println("Signature verified against correct message M.")

	// Now verify the signature against the WRONG message.
	BAD := "Goodbye World!"
	verifier = rep.Verifier(suite, pub)
	err = HashVerify(suite, BAD, verifier, proof)
	fmt.Println("Signature verify against wrong message: " + err.Error())

	// Output:
	// Signature:
	// 00000000  80 63 15 19 7f 91 5f 81  94 40 3b a0 7b cd b2 53  |.c...._..@;.{..S|
	// 00000010  39 e6 09 e8 dd 6b 33 9a  4a fa cc 6b b5 aa ef 52  |9....k3.J..k...R|
	// 00000020  0a 2a ca 87 50 a7 1e 12  a9 d2 8a 7b 64 b8 39 17  |.*..P......{d.9.|
	// 00000030  a0 41 ff 5f 9c d9 a3 0b  b8 0b 67 41 fb 25 ff 5b  |.A._......gA.%.[|
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
func ExampleHashProve_2() {

	// Crypto setup
	suite := suite.Default(nil)
	rand := suite.Cipher([]byte("example"))
	B := suite.Point().Base() // standard base point

	// Create an anonymity ring of random "public keys"
	X := make([]abstract.Point, 3)
	for i := range X { // pick random points
		X[i] = suite.Point().Random(rand)
	}

	// Make just one of them an actual public/private keypair (X[mine],x)
	mine := 2                          // only the signer knows this
	x := suite.Scalar().Random(rand)   // create a private key x
	X[mine] = suite.Point().BaseMul(x) // corresponding public key X

	// Produce the correct linkage tag for the signature,
	// as a pseudorandom base point multiplied by our private key.
	linkScope := []byte("The Linkage Scope")
	linkHash := suite.Cipher(linkScope)
	linkBase := suite.Point().Random(linkHash)
	linkTag := suite.Point().Mul(linkBase, x)

	// Generate the proof predicate: an OR branch for each public key.
	sec := map[string]abstract.Scalar{"x": x}
	pub := map[string]abstract.Point{"B": B, "BT": linkBase, "T": linkTag}
	preds := make([]Predicate, len(X))
	for i := range X {
		name := fmt.Sprintf("X[%d]", i) // "X[0]","X[1]",...
		pub[name] = X[i]                // public point value

		// Predicate indicates knowledge of the private key for X[i]
		// and correspondence of the key with the linkage tag
		preds[i] = And(Rep(name, "x", "B"), Rep("T", "x", "BT"))
	}
	pred := Or(preds...) // make a big Or predicate
	fmt.Printf("Linkable Ring Signature Predicate:\n\t%s\n", pred.String())

	// The prover needs to know which Or branch (mine) is actually true.
	choice := make(map[Predicate]int)
	choice[pred] = mine

	// Generate the signature
	M := "Hello World!" // message we want to sign
	prover := pred.Prover(suite, sec, pub, choice)
	proof, _ := HashProve(suite, M, rand, prover)
	fmt.Print("Linkable Ring Signature:\n" + hex.Dump(proof))

	// Verify the signature
	verifier := pred.Verifier(suite, pub)
	err := HashVerify(suite, M, verifier, proof)
	if err != nil {
		panic("signature failed to verify!")
	}
	fmt.Println("Linkable Ring Signature verified.")

	// Output:
	// Linkable Ring Signature Predicate:
	// 	(X[0]=x*B && T=x*BT) || (X[1]=x*B && T=x*BT) || (X[2]=x*B && T=x*BT)
	// Linkable Ring Signature:
	// 00000000  78 99 26 67 be f4 1a 3c  10 6e d2 d3 1a e1 b4 1d  |x.&g...<.n......|
	// 00000010  1d cf 67 0b 3d 84 9d 3f  61 80 f5 c3 d5 ab ff 16  |..g.=..?a.......|
	// 00000020  99 dd 8a 2d 57 2f 36 6c  86 c7 16 da 1f d4 ae 19  |...-W/6l........|
	// 00000030  bd 3e 10 b9 84 74 f7 a9  73 6e 86 24 e1 58 c3 87  |.>...t..sn.$.X..|
	// 00000040  03 f9 be ce 63 18 e0 37  28 bb 1e d2 ee 69 6f e0  |....c..7(....io.|
	// 00000050  c6 18 8e 2e b5 2c d3 af  ba 7d a4 c2 20 61 07 87  |.....,...}.. a..|
	// 00000060  7f 50 5e d7 4a 03 e3 b7  60 44 6b 3f 3d e0 c0 f7  |.P^.J...`Dk?=...|
	// 00000070  00 9a 23 e7 e8 cf ce dd  8f 07 06 70 62 11 14 4a  |..#........pb..J|
	// 00000080  59 0e fb d0 1e 82 22 38  a9 db f8 40 d2 85 5d 60  |Y....."8...@..]`|
	// 00000090  d6 14 f8 8a 3b e2 5c 46  58 17 ec 2f 6b c0 4f 2e  |....;.\FX../k.O.|
	// 000000a0  d9 ce b7 ac 97 a6 72 d4  a6 5c 4b aa d0 41 e5 d9  |......r..\K..A..|
	// 000000b0  e6 db a8 05 65 32 64 7e  1c cb 20 23 c4 ee 42 1c  |....e2d~.. #..B.|
	// 000000c0  04 9e 16 96 3b 2b d6 ca  72 ec 74 91 06 8a a9 c3  |....;+..r.t.....|
	// 000000d0  e9 86 6a aa 51 16 91 c0  8a 68 b5 d6 cf 78 fb ce  |..j.Q....h...x..|
	// 000000e0  0a c2 a9 d2 4d 3c 76 6e  79 bf a6 eb 45 2d ec 55  |....M<vny...E-.U|
	// 000000f0  b6 24 d3 90 6a 06 36 d2  16 c4 3a 09 62 29 56 34  |.$..j.6...:.b)V4|
	// 00000100  05 07 9a b1 b5 ae 38 cd  ca 8c 0e 95 f1 ec 16 66  |......8........f|
	// 00000110  e0 40 7d ca a2 5d 8d 9a  67 9f 95 9a 77 c4 0a 46  |.@}..]..g...w..F|
	// 00000120  00 d1 38 cf b7 95 b6 28  8c da b2 3b f3 61 43 3b  |..8....(...;.aC;|
	// 00000130  21 db 9b 5a d2 e1 24 87  8a 83 be ef 98 ef 92 99  |!..Z..$.........|
	// 00000140  05 bf ec 1c 58 a5 35 c4  e8 d1 77 32 1b 71 17 62  |....X.5...w2.q.b|
	// 00000150  dd ed 45 97 f0 5c fc 69  ad e7 21 ec 2e a6 12 17  |..E..\.i..!.....|
	// 00000160  0e 98 c1 f7 54 42 44 43  a4 aa da 7c 15 eb 45 8f  |....TBDC...|..E.|
	// 00000170  93 9b e7 86 32 30 1f 0b  3a 70 0d 12 21 c6 9c 09  |....20..:p..!...|
	// Linkable Ring Signature verified.
}
