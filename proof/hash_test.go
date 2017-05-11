package proof

import (
	"encoding/hex"
	"fmt"

	"github.com/dedis/crypto"
	"github.com/dedis/crypto/group/nist"
)

// This example shows how to build classic ElGamal-style digital signatures
// using the Camenisch/Stadler proof framework and HashProver.
func ExampleHashProve_1() {

	// Crypto setup
	suite := nist.NewAES128SHA256P256()
	rand := suite.Cipher([]byte("example"))
	B := suite.Point().Base() // standard base point

	// Create a public/private keypair (X,x)
	x := suite.Scalar().Pick(rand) // create a private key x
	X := suite.Point().Mul(nil, x) // corresponding public key X

	// Generate a proof that we know the discrete logarithm of X.
	M := "Hello World!" // message we want to sign
	rep := Rep("X", "x", "B")
	sec := map[string]kyber.Scalar{"x": x}
	pub := map[string]kyber.Point{"B": B, "X": X}
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
	// 00000000  04 23 62 b1 f9 cb f4 a2  6d 7f 3e 69 cb b6 77 ab  |.#b.....m.>i..w.|
	// 00000010  90 fc 7c db a0 c6 e8 12  f2 0a d4 40 a4 b6 c4 de  |..|........@....|
	// 00000020  9e e8 61 88 5e 50 fd 03  a9 ff 9c a3 c4 29 f7 18  |..a.^P.......)..|
	// 00000030  49 ad 31 0e f9 17 15 1e  3b 8d 0e 2f b2 c4 28 32  |I.1.....;../..(2|
	// 00000040  4a 5c 64 ca 04 eb 33 db  a9 75 9b 01 6b 12 01 ae  |J\d...3..u..k...|
	// 00000050  4e de 7c 6b 53 85 f8 a5  76 ba eb 7e 2e 61 2c a5  |N.|kS...v..~.a,.|
	// 00000060  e8                                                |.|
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
	suite := nist.NewAES128SHA256P256()
	rand := suite.Cipher([]byte("example"))
	B := suite.Point().Base() // standard base point

	// Create an anonymity ring of random "public keys"
	X := make([]kyber.Point, 3)
	for i := range X { // pick random points
		X[i], _ = suite.Point().Pick(nil, rand)
	}

	// Make just one of them an actual public/private keypair (X[mine],x)
	mine := 2                           // only the signer knows this
	x := suite.Scalar().Pick(rand)      // create a private key x
	X[mine] = suite.Point().Mul(nil, x) // corresponding public key X

	// Produce the correct linkage tag for the signature,
	// as a pseudorandom base point multiplied by our private key.
	linkScope := []byte("The Linkage Scope")
	linkHash := suite.Cipher(linkScope)
	linkBase, _ := suite.Point().Pick(nil, linkHash)
	linkTag := suite.Point().Mul(linkBase, x)

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
	// 00000000  04 56 81 70 79 e2 f6 ea  5b 06 a5 f5 72 5d f5 e0  |.V.py...[...r]..|
	// 00000010  b6 e6 d3 90 52 af 84 7a  b1 78 a9 03 f3 29 1e a2  |....R..z.x...)..|
	// 00000020  1a 59 50 28 9b 6c d7 ca  72 25 83 67 2d fe f7 f0  |.YP(.l..r%.g-...|
	// 00000030  96 e9 ae 9b 9e a0 eb 76  7f 74 6d bc 42 18 a1 d1  |.......v.tm.B...|
	// 00000040  0e 04 d8 28 10 ae b9 25  87 e9 a1 c4 fa 1b ff 88  |...(...%........|
	// 00000050  96 bd da 4a 7f 58 c9 b5  57 57 7f 8b ee 4e 00 40  |...J.X..WW...N.@|
	// 00000060  fa 2c 6a 49 74 41 9a c6  7d ac 78 fa 58 35 84 40  |.,jItA..}.x.X5.@|
	// 00000070  2a 95 62 8c 05 5c 75 57  4e 74 22 a9 5f 78 48 22  |*.b..\uWNt"._xH"|
	// 00000080  1f 97 04 f7 a8 0d ec 81  39 31 fb 8b 8b 12 09 74  |........91.....t|
	// 00000090  46 9f 46 22 e9 69 cc 25  c5 b6 23 5b 2a 4b 3d 4c  |F.F".i.%..#[*K=L|
	// 000000a0  10 f7 73 e0 22 00 f3 99  28 be ad 07 8c ef 44 a6  |..s."...(.....D.|
	// 000000b0  d8 e0 ee 5e 04 c7 d1 60  b4 f0 8d e3 bd b3 31 8e  |...^...`......1.|
	// 000000c0  19 9a 56 04 9f da 0c 05  3f 04 42 e4 d3 e3 78 00  |..V.....?.B...x.|
	// 000000d0  d8 bc 31 c2 00 fd 29 64  63 65 e5 9a 1c 5f b4 01  |..1...)dce..._..|
	// 000000e0  ca 14 c5 48 bc 73 60 31  9e 18 7d 93 c8 69 cc c9  |...H.s`1..}..i..|
	// 000000f0  a4 c7 72 e0 c2 a8 2e 47  f5 fa e8 1f de c0 14 52  |..r....G.......R|
	// 00000100  9f 7a a7 5b 04 2e b4 bb  d5 a1 8a 80 4e 48 1e 07  |.z.[........NH..|
	// 00000110  20 e0 f8 9a 6a 9c 5a b7  8b 08 9c 6d c7 0e 9c 9f  | ...j.Z....m....|
	// 00000120  3f 6b d3 34 7e 50 91 6b  87 03 d5 54 b6 87 f1 2d  |?k.4~P.k...T...-|
	// 00000130  4c d6 9e df fe 1b 7f 07  be 5e d5 88 7f 2b b0 58  |L........^...+.X|
	// 00000140  e2 12 62 15 00 04 d8 45  d5 c4 91 77 0c 74 5c 54  |..b....E...w.t\T|
	// 00000150  89 e9 cd 75 9b c5 20 67  26 d8 e4 e8 ed 68 96 51  |...u.. g&....h.Q|
	// 00000160  6f 39 e5 62 e5 c5 24 15  5e 45 69 91 c0 83 2c 6b  |o9.b..$.^Ei...,k|
	// 00000170  33 fe af 75 c2 23 ca 88  b2 a8 c8 be f2 4f f0 e9  |3..u.#.......O..|
	// 00000180  65 af e6 b1 7e e6 eb 40  46 de 61 2f 08 8d 9a 04  |e...~..@F.a/....|
	// 00000190  09 d7 a1 62 83 48 e3 cc  09 af 64 26 df df da d6  |...b.H....d&....|
	// 000001a0  51 62 5d e6 2b 56 b2 b5  3a e1 c8 8c f7 29 8a 13  |Qb].+V..:....)..|
	// 000001b0  75 59 98 ea ce f4 6d d5  d0 62 85 51 8e fe d9 4a  |uY....m..b.Q...J|
	// 000001c0  02 1f 35 03 33 d3 0e 4e  6b b8 fc f9 c9 92 4d e9  |..5.3..Nk.....M.|
	// 000001d0  c3 1c 35 ec 19 43 7c 25  1b b4 70 09 30 08 e3 a1  |..5..C|%..p.0...|
	// 000001e0  e1 42 ed 92 0d 82 63 d3  5a 0e 97 78 e6 74 ce a0  |.B....c.Z..x.t..|
	// 000001f0  24 34 c1 66 7d af 32 9e  59 22 f2 9a 67 3c ea e5  |$4.f}.2.Y"..g<..|
	// 00000200  4f 54 6d 3e 07 f1 1e 6d  18 7f 8b 95 e3 c4 b9 33  |OTm>...m.......3|
	// 00000210  ad 94 69 b5 b4 13 b8 51  2f 24 a7 98 e4 06 f4 b2  |..i....Q/$......|
	// 00000220  f3 ee e8 73 de 78 d1 ab  ff 11 e3 6e df 3d a8 b5  |...s.x.....n.=..|
	// 00000230  13 86 b6 a5 86 f9 a6 ef  ca 77 46 df 8d 3b eb fb  |.........wF..;..|
	// 00000240  00 c8 61 cc fd 7a                                 |..a..z|
	// Linkable Ring Signature verified.
}
