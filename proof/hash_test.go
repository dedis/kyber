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
	// 00000000  02 22 17 82 90 fd 63 78  91 37 12 26 0b 85 a4 5f  |."....cx.7.&..._|
	// 00000010  c4 50 5d 4f 7c da 22 75  81 bd 85 a6 25 b3 ca d8  |.P]O|."u....%...|
	// 00000020  1b 02 d8 91 b8 82 2e 88  69 ba 47 5d 68 f7 8e 56  |........i.G]h..V|
	// 00000030  b5 f0 b9 93 c2 94 10 65  6f 1d 98 5f 17 a8 ef ec  |.......eo.._....|
	// 00000040  45 04 03 f5 a9 11 32 0b  f0 e6 87 a9 0f cd d7 c3  |E.....2.........|
	// 00000050  e8 9e 1f 47 0c 1b 10 52  de e0 4e fe 25 d4 4e 89  |...G...R..N.%.N.|
	// 00000060  97 35 6a 03 ef 39 35 1f  fb 84 5c 1c 55 4d a4 d0  |.5j..95...\.UM..|
	// 00000070  36 9d 5b 2b 34 be 10 bf  6a bd 7f d9 a8 11 51 7c  |6.[+4...j.....Q||
	// 00000080  6c e7 6f b8 02 2f fc 10  c8 d6 40 23 e4 37 05 c5  |l.o../....@#.7..|
	// 00000090  b4 39 de a6 d1 85 f5 c0  be 57 76 83 c0 d4 8e ff  |.9.......Wv.....|
	// 000000a0  2f 82 1e db 29 02 33 5b  1f 1b c5 b8 b5 fd 7b 77  |/...).3[......{w|
	// 000000b0  1c 32 06 3d b6 c0 6b 9b  a6 d6 47 0c 51 69 2f 4f  |.2.=..k...G.Qi/O|
	// 000000c0  2d 38 f5 46 82 a4 c6 f6  34 12 83 a0 32 2e 82 2c  |-8.F....4...2..,|
	// 000000d0  4b fb b3 0c a1 4b a5 e3  27 43 b6 2f ed fa ca 4f  |K....K..'C./...O|
	// 000000e0  93 83 fd 56 cc 43 71 eb  40 46 de 61 2f 08 8d 9a  |...V.Cq.@F.a/...|
	// 000000f0  04 09 d7 a1 62 83 48 e3  cc 09 af 64 26 df df da  |....b.H....d&...|
	// 00000100  d6 51 62 5d e6 2b 9f 75  01 e9 5a b8 dc ec 95 df  |.Qb].+.u..Z.....|
	// 00000110  9d c9 4c f8 45 5e 3e fa  93 d6 5b 02 af 7b 66 26  |..L.E^>...[..{f&|
	// 00000120  b3 b4 5a a2 c0 1c 56 b2  b5 3a e1 c8 8c f7 29 8a  |..Z...V..:....).|
	// 00000130  13 75 59 98 ea ce f4 6d  d5 d0 62 85 51 8e fe d9  |.uY....m..b.Q...|
	// 00000140  4a 02 1f 35 03 33 d3 63  d3 5a 0e 97 78 e6 74 ce  |J..5.3.c.Z..x.t.|
	// 00000150  a0 24 34 c1 66 7d af 32  9e 59 22 f2 9a 67 3c ea  |.$4.f}.2.Y"..g<.|
	// 00000160  e5 4f 54 6d 3e 07 56 29  e3 95 12 f5 35 39 58 8a  |.OTm>.V)....59X.|
	// 00000170  e3 a2 6e c0 4e b1 74 51  d8 2b 1e f7 7c 1d fe fc  |..n.N.tQ.+..|...|
	// 00000180  75 29 8d f7 3e 18                                 |u)..>.|
	// Linkable Ring Signature verified.
}
