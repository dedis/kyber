package proof

import (
	"fmt"
	"encoding/hex"
	"dissent/crypto"
	"dissent/crypto/openssl"
)


// This example shows how to build classic ElGamal-style digital signatures
// using the Camenisch/Stadler proof framework and HashProver.
func ExampleHashProve_1() {

	// Crypto setup
	suite := openssl.NewAES128SHA256P256()
	rand := crypto.HashStream(suite, []byte("example"), nil)
	B := suite.Point().Base()		// standard base point

	// Create a public/private keypair (X,x)
	x := suite.Secret().Pick(rand)		// create a private key x
	X := suite.Point().Mul(nil,x)		// corresponding public key X

	// Generate a proof that we know the discrete logarithm of X.
	M := "Hello World!"			// message we want to sign
	rep := Rep("X","x","B")
	sec := map[string]crypto.Secret{"x":x}
	pub := map[string]crypto.Point{"B":B, "X":X}
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
	// 00000000  02 a7 88 0a 50 7e 71 48  03 0d a8 6c 31 f7 01 ed  |....P~qH...l1...|
	// 00000010  c5 ea 92 5a b3 35 85 42  43 ec b2 72 1c 50 10 88  |...Z.5.BC..r.P..|
	// 00000020  fe 72 86 62 f3 a6 3a 80  57 12 ff bf b6 1f 76 c5  |.r.b..:.W.....v.|
	// 00000030  dd e1 5e e6 7b 4b ac 0a  60 6f 1e 07 cd 52 43 07  |..^.{K..`o...RC.|
	// 00000040  d2                                                |.|
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
	rand := crypto.HashStream(suite, []byte("example"), nil)
	B := suite.Point().Base()		// standard base point

	// Create an anonymity ring of random "public keys"
	X := make([]crypto.Point,3)
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
	linkHash := crypto.HashStream(suite, linkScope, nil)
	linkBase,_ := suite.Point().Pick(nil, linkHash)
	linkTag := suite.Point().Mul(linkBase, x)

	// Generate the proof predicate: an OR branch for each public key.
	sec := map[string]crypto.Secret{"x":x}
	pub := map[string]crypto.Point{"B":B, "BT":linkBase, "T":linkTag}
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
	// 00000000  02 34 a1 40 28 8f 57 5a  17 a8 29 fc dd bf 75 6e  |.4.@(.WZ..)...un|
	// 00000010  fe fc e1 da 0d df 28 fd  cf eb 93 eb da 15 7c ba  |......(.......|.|
	// 00000020  d0 02 6e 04 dd e2 aa 97  2b 43 f6 a4 3a c4 30 c9  |..n.....+C..:.0.|
	// 00000030  fc f5 d2 61 18 47 6b f6  a9 6e 7a fb 6e 4c 5a 3b  |...a.Gk..nz.nLZ;|
	// 00000040  57 bb 02 8b 9c 68 38 1b  06 5f ee 64 3c 9d 05 8c  |W....h8.._.d<...|
	// 00000050  2c 3d 3e 7b eb 7c 3a df  25 bd 24 02 79 c3 92 25  |,=>{.|:.%.$.y..%|
	// 00000060  82 b1 37 03 dc 00 c7 30  ab 6a 6b e8 d1 3b a0 1e  |..7....0.jk..;..|
	// 00000070  5d e3 06 a3 04 5b 42 a3  12 5a f3 4f 7b fc ee 9c  |]....[B..Z.O{...|
	// 00000080  e5 9f c5 86 02 76 34 8a  fe 25 f9 a2 ce f9 0f a8  |.....v4..%......|
	// 00000090  d2 83 9c 4c e9 68 e1 f0  37 66 2c b8 90 6e da ba  |...L.h..7f,..n..|
	// 000000a0  83 39 c8 71 8a 02 c9 d8  ab a2 69 64 0e ab d7 b0  |.9.q......id....|
	// 000000b0  90 5e ac 2c ba a8 a0 d6  40 81 6c b9 e3 d2 4c 89  |.^.,....@.l...L.|
	// 000000c0  b5 18 a6 48 8c ff 86 73  0a 3e 4e 33 83 d4 b7 15  |...H...s.>N3....|
	// 000000d0  b3 4b 89 da 15 07 66 81  4d ec 53 f4 aa 13 02 73  |.K....f.M.S....s|
	// 000000e0  1e 50 62 28 5b 5b 6f 3f  71 59 90 e6 14 23 63 fb  |.Pb([[o?qY...#c.|
	// 000000f0  d2 dd dc 39 e0 2c 32 c1  e3 fd 5e 28 1c c5 19 ec  |...9.,2...^(....|
	// 00000100  e1 d9 d9 f7 38 40 da 41  24 d0 83 72 a6 78 8e 28  |....8@.A$..r.x.(|
	// 00000110  79 79 ab 8e 7c 95 4a 60  9f 00 f9 0b 29 d0 ae f0  |yy..|.J`....)...|
	// 00000120  27 65 3b 52 ed 7d a2 5f  24 d6 46 ca e8 88 43 e7  |'e;R.}._$.F...C.|
	// 00000130  ed 9d d9 dd 68 2e f6 4e  b6 fa b2 e6 4f c0 65 50  |....h..N....O.eP|
	// 00000140  09 5c 6a c4 dd 98 66 6f  e6 c1 6f 9a bb 4e d6 4d  |.\j...fo..o..N.M|
	// 00000150  a3 7d 82 8d 83 e6 f6 aa  5f 25 c9 24 95 76 af c1  |.}......_%.$.v..|
	// 00000160  7e ec eb 1e 98 15 2f f3  df ac 9e 65 3b ef 75 1e  |~...../....e;.u.|
	// 00000170  67 78 63 c9 4f 91 b2 9f  8c c4 49 3f 10 0d 65 51  |gxc.O.....I?..eQ|
	// 00000180  bc fe 41 c9 2b c2                                 |..A.+.|
	// Linkable Ring Signature verified.
}

