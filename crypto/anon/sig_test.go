package anon

import (
	"fmt"
	"bytes"
	"encoding/hex"
	"dissent/crypto"
	"dissent/crypto/openssl"
)

// This example demonstrates signing and signature verification
// using a trivial "anonymity set" of size 1, i.e., no anonymity.
// In this special case the signing scheme devolves to
// producing traditional ElGamal signatures:
// the resulting signatures are exactly the same length
// and represent essentially the same computational cost.
func ExampleSign_1() {

	// Crypto setup
	suite := openssl.NewAES128SHA256P256()
	rand := crypto.HashStream(suite, []byte("example"), nil)

	// Create a public/private keypair (X[mine],x)
	X := make([]crypto.Point,1)
	mine := 0				// which public key is mine
	x := suite.Secret().Pick(rand)		// create a private key x
	X[mine] = suite.Point().Mul(nil,x)	// corresponding public key X

	// Generate the signature
	M := []byte("Hello World!")		// message we want to sign
	sig := Sign(suite, rand, M, Set(X), nil, mine, x)
	fmt.Print("Signature:\n"+hex.Dump(sig))

	// Verify the signature against the correct message
	tag,err := Verify(suite, M, Set(X), nil, sig)
	if err != nil {
		panic(err.Error())
	}
	if tag == nil || len(tag) != 0 {
		panic("Verify returned wrong tag")
	}
	fmt.Println("Signature verified against correct message.")

	// Verify the signature against the wrong message
	BAD := []byte("Goodbye world!")
	tag,err = Verify(suite, BAD, Set(X), nil, sig)
	if err == nil || tag != nil {
		panic("Signature verified against wrong message!?")
	}
	fmt.Println("Verifying against wrong message: "+err.Error())

	// Output:
	// Signature:
	// 00000000  aa ed 0d ac 14 0d 60 d9  88 8b 3c c2 86 0b f5 79  |......`...<....y|
	// 00000010  bd 1e ec 0c e8 03 83 44  9b 3b 64 c5 14 4e 87 c4  |.......D.;d..N..|
	// 00000020  58 8c a0 be c8 4c 15 c9  83 56 70 60 23 7a bd 2a  |X....L...Vp`#z.*|
	// 00000030  1b 64 f1 71 09 ea 0f b3  0d 3d 05 a7 c0 95 c0 94  |.d.q.....=......|
	// Signature verified against correct message.
	// Verifying against wrong message: invalid signature
}

// This example demonstrates how to create unlinkable anonymity-set signatures,
// and to verify them,
// using a small anonymity set containing three public keys.
func ExampleSign_anonSet() {

	// Crypto setup
	suite := openssl.NewAES128SHA256P256()
	rand := crypto.HashStream(suite, []byte("example"), nil)

	// Create an anonymity set of random "public keys"
	X := make([]crypto.Point,3)
	for i := range(X) {			// pick random points
		X[i],_ = suite.Point().Pick(nil,rand)
	}

	// Make just one of them an actual public/private keypair (X[mine],x)
	mine := 1				// only the signer knows this
	x := suite.Secret().Pick(rand)		// create a private key x
	X[mine] = suite.Point().Mul(nil,x)	// corresponding public key X

	// Generate the signature
	M := []byte("Hello World!")		// message we want to sign
	sig := Sign(suite, rand, M, Set(X), nil, mine, x)
	fmt.Print("Signature:\n"+hex.Dump(sig))

	// Verify the signature against the correct message
	tag,err := Verify(suite, M, Set(X), nil, sig)
	if err != nil {
		panic(err.Error())
	}
	if tag == nil || len(tag) != 0 {
		panic("Verify returned wrong tag")
	}
	fmt.Println("Signature verified against correct message.")

	// Verify the signature against the wrong message
	BAD := []byte("Goodbye world!")
	tag,err = Verify(suite, BAD, Set(X), nil, sig)
	if err == nil || tag != nil {
		panic("Signature verified against wrong message!?")
	}
	fmt.Println("Verifying against wrong message: "+err.Error())

	// Output:
	// Signature:
	// 00000000  ee e9 af 72 c7 51 de 92  b8 fd 32 c9 0f 01 fe d9  |...r.Q....2.....|
	// 00000010  01 80 2c 21 90 48 56 6f  0a 9f e0 dc 70 0c 97 6c  |..,!.HVo....p..l|
	// 00000020  a2 5f 24 d6 46 ca e8 88  43 e7 ed 9d d9 dd 68 2e  |._$.F...C.....h.|
	// 00000030  f6 4e b6 fa b2 e6 4f c0  65 50 09 5c 6a c4 dd 98  |.N....O.eP.\j...|
	// 00000040  2b 95 e9 d3 e5 80 49 3e  33 75 6c 33 ba 9e 53 f2  |+.....I>3ul3..S.|
	// 00000050  19 62 f3 2b e2 0c 4b f4  c1 bd b9 bd b3 aa b8 2f  |.b.+..K......../|
	// 00000060  6f 3f 71 59 90 e6 14 23  63 fb d2 dd dc 39 e0 2c  |o?qY...#c....9.,|
	// 00000070  32 c1 e3 fd 5e 28 1c c5  19 ec e1 d9 d9 f7 38 40  |2...^(........8@|
	// Signature verified against correct message.
	// Verifying against wrong message: invalid signature
}

// This example demonstrates the creation of linkable anonymity set signatures,
// and verification, using an anonymity set containing three public keys.
// We produce four signatures, two from each of two private key-holders,
// demonstrating how the resulting verifiable tags distinguish
// signatures by the same key-holder from signatures by different key-holders.
func ExampleSign_linkable() {

	// Crypto setup
	suite := openssl.NewAES128SHA256P256()
	rand := crypto.HashStream(suite, []byte("example"), nil)

	// Create an anonymity set of random "public keys"
	X := make([]crypto.Point,3)
	for i := range(X) {			// pick random points
		X[i],_ = suite.Point().Pick(nil,rand)
	}

	// Make two actual public/private keypairs (X[mine],x)
	mine1 := 1				// only the signer knows this
	mine2 := 2
	x1 := suite.Secret().Pick(rand)		// create a private key x
	x2 := suite.Secret().Pick(rand)
	X[mine1] = suite.Point().Mul(nil,x1)	// corresponding public key X
	X[mine2] = suite.Point().Mul(nil,x2)

	// Generate two signatures using x1 and two using x2
	M := []byte("Hello World!")		// message we want to sign
	S := []byte("My Linkage Scope")		// scope for linkage tags
	var sig [4][]byte
	sig[0] = Sign(suite, rand, M, Set(X), S, mine1, x1)
	sig[1] = Sign(suite, rand, M, Set(X), S, mine1, x1)
	sig[2] = Sign(suite, rand, M, Set(X), S, mine2, x2)
	sig[3] = Sign(suite, rand, M, Set(X), S, mine2, x2)
	for i := range(sig) {
		fmt.Printf("Signature %d:\n%s",i,hex.Dump(sig[i]))
	}

	// Verify the signatures against the correct message
	var tag [4][]byte
	for i := range(sig) {
		goodtag,err := Verify(suite, M, Set(X), S, sig[i])
		if err != nil {
			panic(err.Error())
		}
		tag[i] = goodtag
		if tag[i] == nil || len(tag[i]) != suite.PointLen() {
			panic("Verify returned invalid tag")
		}
		fmt.Printf("Sig%d tag: %s\n",i,
				hex.EncodeToString(tag[i]))

		// Verify the signature against the wrong message
		BAD := []byte("Goodbye world!")
		badtag,err := Verify(suite, BAD, Set(X), S, sig[i])
		if err == nil || badtag != nil {
			panic("Signature verified against wrong message!?")
		}
	}
	if !bytes.Equal(tag[0],tag[1]) || !bytes.Equal(tag[2],tag[3]) ||
			bytes.Equal(tag[0],tag[2]) {
		panic("tags aren't coming out right!")
	}

	// Output:
	// Signature 0:
	// 00000000  d3 b1 6a 56 36 16 f5 42  7c e6 f0 05 69 8f f8 3e  |..jV6..B|...i..>|
	// 00000010  d3 2b 33 87 55 7f 12 fd  04 d1 2f a2 5e 4d c8 b1  |.+3.U...../.^M..|
	// 00000020  66 6f e6 c1 6f 9a bb 4e  d6 4d a3 7d 82 8d 83 e6  |fo..o..N.M.}....|
	// 00000030  f6 aa 5f 25 c9 24 95 76  af c1 7e ec eb 1e 98 15  |.._%.$.v..~.....|
	// 00000040  54 8f 02 75 f8 f6 c5 3e  35 9d 8f 27 9c 71 3d 7b  |T..u...>5..'.q={|
	// 00000050  4c 69 bc a5 b2 4c d7 c1  48 e7 03 8d 57 2d f8 c7  |Li...L..H...W-..|
	// 00000060  a2 5f 24 d6 46 ca e8 88  43 e7 ed 9d d9 dd 68 2e  |._$.F...C.....h.|
	// 00000070  f6 4e b6 fa b2 e6 4f c0  65 50 09 5c 6a c4 dd 98  |.N....O.eP.\j...|
	// 00000080  02 5b 95 c5 b8 60 4c 90  6d 8a 64 87 87 59 e0 a7  |.[...`L.m.d..Y..|
	// 00000090  69 fd ca e6 4c a5 bd af  7d 80 dc 7d d7 c8 e4 f8  |i...L...}..}....|
	// 000000a0  d9                                                |.|
	// Signature 1:
	// 00000000  1d d3 c9 7b 78 5a 4d 57  85 b4 0a bd 8e e8 a5 db  |...{xZMW........|
	// 00000010  ec 50 01 78 c2 87 51 d2  2a d0 9c 1c 90 9e 6b e7  |.P.x..Q.*.....k.|
	// 00000020  35 ad ee 4a d3 3b a2 e5  d5 ae f7 18 34 64 d1 96  |5..J.;......4d..|
	// 00000030  54 2c 49 60 17 0e eb a7  e3 0c 72 80 55 b2 34 86  |T,I`......r.U.4.|
	// 00000040  60 d1 4c 85 71 66 f5 ab  1d fc c9 04 74 3a 91 65  |`.L.qf......t:.e|
	// 00000050  83 6e 89 1b f2 dd b4 ab  a2 43 aa d7 f7 4b 16 c8  |.n.......C...K..|
	// 00000060  42 91 87 52 e5 93 dc 2c  8d 43 f8 71 02 d8 27 c6  |B..R...,.C.q..'.|
	// 00000070  97 46 9a 93 c1 54 b8 9a  22 01 09 b4 41 ce 23 4f  |.F...T.."...A.#O|
	// 00000080  02 5b 95 c5 b8 60 4c 90  6d 8a 64 87 87 59 e0 a7  |.[...`L.m.d..Y..|
	// 00000090  69 fd ca e6 4c a5 bd af  7d 80 dc 7d d7 c8 e4 f8  |i...L...}..}....|
	// 000000a0  d9                                                |.|
	// Signature 2:
	// 00000000  9f 9d 0f bf 00 b7 79 fb  ad 2b 36 fa 62 1e 66 76  |......y..+6.b.fv|
	// 00000010  fe 6a 1a 9f 7b ed e2 1f  1c 47 02 41 04 1e 67 a2  |.j..{....G.A..g.|
	// 00000020  e6 1e a9 a0 c6 89 15 b9  c3 be e5 92 69 c8 48 dc  |............i.H.|
	// 00000030  a5 82 12 48 0a ec 57 ef  fe e5 f2 ae ed c1 45 c7  |...H..W.......E.|
	// 00000040  70 52 c2 ae 47 6d 4e b3  5b 19 1c da 11 6c ec 15  |pR..GmN.[....l..|
	// 00000050  8f 8d 18 ca ab a9 56 df  23 cd c7 29 d9 ad 9f 9d  |......V.#..)....|
	// 00000060  40 2b 48 f9 50 91 68 80  91 d0 ca c8 89 a4 3a 29  |@+H.P.h.......:)|
	// 00000070  97 c5 6e 47 df 55 23 51  94 45 51 0c cf 33 de 7d  |..nG.U#Q.EQ..3.}|
	// 00000080  03 ab 1d f5 17 4b 14 ef  01 2e fb ff 5c 01 a8 f7  |.....K......\...|
	// 00000090  15 68 36 fa ba 2f 57 63  1c 62 d4 c8 7d 51 28 c6  |.h6../Wc.b..}Q(.|
	// 000000a0  f1                                                |.|
	// Signature 3:
	// 00000000  50 db 36 5d 11 be 0e 05  3f 50 3d 98 69 33 c3 73  |P.6]....?P=.i3.s|
	// 00000010  bc 1f e0 59 47 b8 c9 34  8b 34 9a 43 83 1e cc 2a  |...YG..4.4.C...*|
	// 00000020  4d a6 e9 c0 49 0b fd bd  c2 9c 08 05 c5 b9 fe 73  |M...I..........s|
	// 00000030  b5 53 24 f0 74 5a 45 aa  06 fe b5 84 2f 2a 2f 61  |.S$.tZE...../*/a|
	// 00000040  76 85 c3 65 1c 2e d8 bc  fa da cf 27 ee 37 03 af  |v..e.......'.7..|
	// 00000050  08 1f 8f 5c 10 57 f2 40  43 27 88 58 07 1e 8d 7a  |...\.W.@C'.X...z|
	// 00000060  88 82 55 f3 c5 13 d1 01  1c 9c e7 75 99 2c bb 8c  |..U........u.,..|
	// 00000070  39 8e a2 3b f3 09 5a fc  de 7b ae cd f8 f6 e8 20  |9..;..Z..{..... |
	// 00000080  03 ab 1d f5 17 4b 14 ef  01 2e fb ff 5c 01 a8 f7  |.....K......\...|
	// 00000090  15 68 36 fa ba 2f 57 63  1c 62 d4 c8 7d 51 28 c6  |.h6../Wc.b..}Q(.|
	// 000000a0  f1                                                |.|
	// Sig0 tag: 025b95c5b8604c906d8a64878759e0a769fdcae64ca5bdaf7d80dc7dd7c8e4f8d9
	// Sig1 tag: 025b95c5b8604c906d8a64878759e0a769fdcae64ca5bdaf7d80dc7dd7c8e4f8d9
	// Sig2 tag: 03ab1df5174b14ef012efbff5c01a8f7156836faba2f57631c62d4c87d5128c6f1
	// Sig3 tag: 03ab1df5174b14ef012efbff5c01a8f7156836faba2f57631c62d4c87d5128c6f1

}

