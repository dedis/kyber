package proof

import (
	"encoding/hex"
	"fmt"
	"github.com/dedis/crypto/abstract"
	"github.com/dedis/crypto/openssl"
)

// This example shows how to build classic ElGamal-style digital signatures
// using the Camenisch/Stadler proof framework and HashProver.
func ExampleHashProve_1() {

	// Crypto setup
	suite := openssl.NewAES128SHA256P256()
	rand := suite.Cipher([]byte("example"))
	B := suite.Point().Base() // standard base point

	// Create a public/private keypair (X,x)
	x := suite.Secret().Pick(rand) // create a private key x
	X := suite.Point().Mul(nil, x) // corresponding public key X

	// Generate a proof that we know the discrete logarithm of X.
	M := "Hello World!" // message we want to sign
	rep := Rep("X", "x", "B")
	sec := map[string]abstract.Secret{"x": x}
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
	// 00000000  02 23 62 b1 f9 cb f4 a2  6d 7f 3e 69 cb b6 77 ab  |.#b.....m.>i..w.|
	// 00000010  90 fc 7c db a0 c6 e8 12  f2 0a d4 40 a4 b6 c4 de  |..|........@....|
	// 00000020  9e ac 50 83 66 b9 9f 55  f4 79 48 28 66 cc 25 fb  |..P.f..U.yH(f.%.|
	// 00000030  16 60 d5 0f 88 d6 8d af  97 24 5d 00 ec de 2c 9b  |.`.......$]...,.|
	// 00000040  ed                                                |.|
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
	suite := openssl.NewAES128SHA256P256()
	rand := suite.Cipher([]byte("example"))
	B := suite.Point().Base() // standard base point

	// Create an anonymity ring of random "public keys"
	X := make([]abstract.Point, 3)
	for i := range X { // pick random points
		X[i], _ = suite.Point().Pick(nil, rand)
	}

	// Make just one of them an actual public/private keypair (X[mine],x)
	mine := 2                           // only the signer knows this
	x := suite.Secret().Pick(rand)      // create a private key x
	X[mine] = suite.Point().Mul(nil, x) // corresponding public key X

	// Produce the correct linkage tag for the signature,
	// as a pseudorandom base point multiplied by our private key.
	linkScope := []byte("The Linkage Scope")
	linkHash := suite.Cipher(linkScope)
	linkBase, _ := suite.Point().Pick(nil, linkHash)
	linkTag := suite.Point().Mul(linkBase, x)

	// Generate the proof predicate: an OR branch for each public key.
	sec := map[string]abstract.Secret{"x": x}
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
	//	(X[0]=x*B && T=x*BT) || (X[1]=x*B && T=x*BT) || (X[2]=x*B && T=x*BT)
	// Linkable Ring Signature:
	// 00000000  02 c5 52 b1 46 fa 2b 76  7a a5 87 bc 9f 96 87 49  |..R.F.+vz......I|
	// 00000010  1b 54 ce 9b 4f 03 61 34  d2 6e 6c cd 54 c8 7e 04  |.T..O.a4.nl.T.~.|
	// 00000020  a7 03 5d 11 cd 57 df 11  af 29 35 f8 80 4a a2 76  |..]..W...)5..J.v|
	// 00000030  24 a6 d5 e3 6b ab 14 6b  95 26 7d 35 8a c8 48 cd  |$...k..k.&}5..H.|
	// 00000040  29 1c 03 40 75 ba 0d 6f  5c 76 68 47 02 2d 20 8f  |)..@u..o\vhG.- .|
	// 00000050  0e bf e1 f9 fe 3b 0f 79  78 2c e3 fb b7 88 69 68  |.....;.yx,....ih|
	// 00000060  7a 5e 56 02 f0 af 32 35  03 c5 44 88 81 2e a2 3e  |z^V...25..D....>|
	// 00000070  32 6f 3d a1 79 39 31 8d  c4 c1 63 c5 37 61 ef a8  |2o=.y91...c.7a..|
	// 00000080  66 13 63 70 03 72 2b cf  72 f3 d3 62 fc e8 e3 41  |f.cp.r+.r..b...A|
	// 00000090  d0 73 f2 01 0d 8f 01 d9  f7 56 26 79 f8 37 f1 59  |.s.......V&y.7.Y|
	// 000000a0  e7 40 72 fb 0e 02 35 15  69 c5 ca 3a 00 40 f6 31  |.@r...5.i..:.@.1|
	// 000000b0  ff 19 47 6e 03 aa f9 04  db 14 84 92 73 3f ae 22  |..Gn........s?."|
	// 000000c0  19 9d c0 22 56 3f c6 f6  34 12 83 a0 32 2e 82 2c  |..."V?..4...2..,|
	// 000000d0  4b fb b3 0c a1 4b a5 e3  27 43 b6 2f ed fa ca 4f  |K....K..'C./...O|
	// 000000e0  93 83 fd 56 cc 43 71 eb  40 46 de 3b a1 91 f9 24  |...V.Cq.@F.;...$|
	// 000000f0  93 30 f8 2b eb b6 a0 ef  31 22 46 b7 64 f5 cf 79  |.0.+....1"F.d..y|
	// 00000100  d7 7b 7b 96 91 09 99 22  4e e0 94 f7 0f 9a c0 e8  |.{{...."N.......|
	// 00000110  f1 97 85 92 aa 01 86 f9  39 7b 5d 9d 52 5b d7 d8  |........9{].R[..|
	// 00000120  1d 7b 1c 4f dc cf 35 4f  8e 91 3c 11 27 9b 5f 3c  |.{.O..5O..<.'._<|
	// 00000130  61 19 44 96 76 ff 91 88  74 90 98 56 1a 57 27 75  |a.D.v...t..V.W'u|
	// 00000140  8b 31 a7 40 76 92 08 27  b2 b7 99 f0 80 6d 66 2d  |.1.@v..'.....mf-|
	// 00000150  e2 5f 0d c8 cd b1 3e 46  90 eb d4 42 c4 1c 96 9b  |._....>F...B....|
	// 00000160  93 aa 4e 7e 29 4f 6a bb  ef 66 b1 31 79 11 54 49  |..N~)Oj..f.1y.TI|
	// 00000170  8c 01 f5 43 b0 2d 2c 06  97 bc cb b1 4d 9b b7 cd  |...C.-,.....M...|
	// 00000180  a5 02 92 fa 3a 2b                                 |....:+|
	// Linkable Ring Signature verified.
}
