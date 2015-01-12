package proof

import (
	"fmt"
	"encoding/hex"
	"github.com/dedis/crypto/abstract"
	"github.com/dedis/crypto/openssl"
)


// This example shows how to build classic ElGamal-style digital signatures
// using the Camenisch/Stadler proof framework and HashProver.
func ExampleHashProve_1() {

	// Crypto setup
	suite := openssl.NewAES128SHA256P256()
	rand := abstract.HashStream(suite, []byte("example"), nil)
	B := suite.Point().Base()		// standard base point

	// Create a public/private keypair (X,x)
	x := suite.Secret().Pick(rand)		// create a private key x
	X := suite.Point().Mul(nil,x)		// corresponding public key X

	// Generate a proof that we know the discrete logarithm of X.
	M := "Hello World!"			// message we want to sign
	rep := Rep("X","x","B")
	sec := map[string]abstract.Secret{"x":x}
	pub := map[string]abstract.Point{"B":B, "X":X}
	prover := rep.Prover(suite, sec, pub, nil)
	proof,_ := HashProve(suite, M, rand, prover)
	fmt.Print("Signature:\n"+hex.Dump(proof))

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
	fmt.Println("Signature verify against wrong message: "+err.Error())

	// Output:
	// Signature:
	// 00000000  02 fd dc 29 56 ef d2 87  05 a6 af c2 c9 7d 6a 58  |...)V........}jX|
	// 00000010  74 96 a5 b2 10 82 2c 17  71 a4 43 db 37 14 42 48  |t.....,.q.C.7.BH|
	// 00000020  4a 7f cd b5 49 f6 72 ab  c4 8c 2f ef 0c 47 da c1  |J...I.r.../..G..|
	// 00000030  89 2b 52 ef fe 76 ec aa  1e 0e 1d 47 c7 a4 99 94  |.+R..v.....G....|
	// 00000040  cd                                                |.|
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
	rand := abstract.HashStream(suite, []byte("example"), nil)
	B := suite.Point().Base()		// standard base point

	// Create an anonymity ring of random "public keys"
	X := make([]abstract.Point,3)
	for i := range(X) {			// pick random points
		X[i],_ = suite.Point().Pick(nil,rand)
	}

	// Make just one of them an actual public/private keypair (X[mine],x)
	mine := 2				// only the signer knows this
	x := suite.Secret().Pick(rand)		// create a private key x
	X[mine] = suite.Point().Mul(nil,x)	// corresponding public key X

	// Produce the correct linkage tag for the signature,
	// as a pseudorandom base point multiplied by our private key.
	linkScope := []byte("The Linkage Scope")
	linkHash := abstract.HashStream(suite, linkScope, nil)
	linkBase,_ := suite.Point().Pick(nil, linkHash)
	linkTag := suite.Point().Mul(linkBase, x)

	// Generate the proof predicate: an OR branch for each public key.
	sec := map[string]abstract.Secret{"x":x}
	pub := map[string]abstract.Point{"B":B, "BT":linkBase, "T":linkTag}
	preds := make([]Predicate, len(X))
	for i := range(X) {
		name := fmt.Sprintf("X[%d]",i)	// "X[0]","X[1]",...
		pub[name] = X[i]		// public point value

		// Predicate indicates knowledge of the private key for X[i]
		// and correspondence of the key with the linkage tag
		preds[i] = And(Rep(name,"x","B"),Rep("T","x","BT"))
	}
	pred := Or(preds...)			// make a big Or predicate
	fmt.Printf("Linkable Ring Signature Predicate:\n\t%s\n",pred.String())

	// The prover needs to know which Or branch (mine) is actually true.
	choice := make(map[Predicate]int)
	choice[pred] = mine

	// Generate the signature
	M := "Hello World!"			// message we want to sign
	prover := pred.Prover(suite, sec, pub, choice)
	proof,_ := HashProve(suite, M, rand, prover)
	fmt.Print("Linkable Ring Signature:\n"+hex.Dump(proof))

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
	// 00000000  03 35 88 b1 96 57 7e 68  ea 8d 55 6f 50 9a 8b 2a  |.5...W~h..UoP..*|
	// 00000010  62 f0 99 ee e6 06 5e 87  35 7c 39 db a8 53 b7 de  |b.....^.5|9..S..|
	// 00000020  e5 03 57 6f a7 5d 73 2d  fc f9 be f7 a2 11 c7 33  |..Wo.]s-.......3|
	// 00000030  23 d9 a7 2f 52 38 d1 d5  ca 61 e8 bb 8f 49 95 b6  |#../R8...a...I..|
	// 00000040  dc 58 03 17 e3 61 11 6e  2c f8 12 fd ff 6d 1b d9  |.X...a.n,....m..|
	// 00000050  4d da 2a a2 54 b1 d7 18  0c eb 8d 68 d8 c5 12 c8  |M.*.T......h....|
	// 00000060  d4 fd da 02 39 b3 5d 18  e4 e5 b5 54 05 12 0f 99  |....9.]....T....|
	// 00000070  92 87 18 4f 9b 5e 4f b7  cd f0 b3 fc 9c 99 7d fe  |...O.^O.......}.|
	// 00000080  66 af 02 fa 03 c4 b9 f0  a5 a2 dd 64 af 00 b7 fd  |f..........d....|
	// 00000090  97 7f 91 74 8a 7b 18 38  4b 1b 48 a8 e2 cc be 11  |...t.{.8K.H.....|
	// 000000a0  48 ab 5d 79 3d 03 5c 0e  f2 7a 0c cc bb 12 cb 31  |H.]y=.\..z.....1|
	// 000000b0  f4 de fb 40 8f ea 18 e3  d0 6f fd da 61 1e ba 63  |...@.....o..a..c|
	// 000000c0  11 47 50 92 cf 1e 41 7a  bb b4 ef 27 d7 ce 88 99  |.GP...Az...'....|
	// 000000d0  d9 2f e1 9d 69 59 58 13  d6 18 da 7b a1 57 e0 09  |./..iYX....{.W..|
	// 000000e0  5d e2 1e 48 3f ca d1 3b  09 b8 54 9f b1 0b 4d fc  |]..H?..;..T...M.|
	// 000000f0  6b 2c 3f 32 d6 20 16 ed  89 a3 be 09 97 33 74 02  |k,?2. .......3t.|
	// 00000100  94 c6 7d f1 55 71 4c 52  7f bf df 76 d4 2a e2 89  |..}.UqLR...v.*..|
	// 00000110  47 57 29 c8 db 6a 88 7b  8a bd 5e b4 de 4b 97 fa  |GW)..j.{..^..K..|
	// 00000120  23 13 06 d9 ef f4 cd 81  38 63 31 f1 fd 65 ac 28  |#.......8c1..e.(|
	// 00000130  1a e5 1b 7c d2 14 a0 58  05 2d c1 61 aa 85 c7 88  |...|...X.-.a....|
	// 00000140  5b cf 04 b5 96 9c 66 48  3c bf ec 24 7c 25 e7 de  |[.....fH<..$|%..|
	// 00000150  5f 93 53 09 6b cc 2b 06  2f 7b 43 95 d4 0b c1 c4  |_.S.k.+./{C.....|
	// 00000160  f8 06 33 e2 8a 56 73 b4  f3 f8 12 c0 ac 0a 15 8a  |..3..Vs.........|
	// 00000170  28 57 47 a0 d3 b7 b3 03  d4 a2 f8 35 54 ed c5 ef  |(WG........5T...|
	// 00000180  87 2d e2 c3 e1 ed                                 |.-....|
	// Linkable Ring Signature verified.
}

