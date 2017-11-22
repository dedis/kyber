package anon

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/dedis/kyber"
	"github.com/dedis/kyber/group/edwards25519"
	"github.com/dedis/kyber/util/random"
)

// This example demonstrates signing and signature verification
// using a trivial "anonymity set" of size 1, i.e., no anonymity.
// In this special case the signing scheme devolves to
// producing traditional ElGamal signatures:
// the resulting signatures are exactly the same length
// and represent essentially the same computational cost.
func Example_sign1() {

	// Crypto setup
	suite := edwards25519.NewAES128SHA256Ed25519()
	rand := suite.Cipher([]byte("example"))

	// Create a public/private keypair (X[mine],x)
	X := make([]kyber.Point, 1)
	mine := 0                           // which public key is mine
	x := suite.Scalar().Pick(rand)      // create a private key x
	X[mine] = suite.Point().Mul(x, nil) // corresponding public key X

	// Generate the signature
	M := []byte("Hello World!") // message we want to sign
	sig := Sign(suite, rand, M, Set(X), nil, mine, x)
	fmt.Print("Signature:\n" + hex.Dump(sig))

	// Verify the signature against the correct message
	tag, err := Verify(suite, M, Set(X), nil, sig)
	if err != nil {
		panic(err.Error())
	}
	if tag == nil || len(tag) != 0 {
		panic("Verify returned wrong tag")
	}
	fmt.Println("Signature verified against correct message.")

	// Verify the signature against the wrong message
	BAD := []byte("Goodbye world!")
	tag, err = Verify(suite, BAD, Set(X), nil, sig)
	if err == nil || tag != nil {
		panic("Signature verified against wrong message!?")
	}
	fmt.Println("Verifying against wrong message: " + err.Error())

	// Output:
	// Signature:
	// 00000000  b3 88 46 02 de 19 a3 10  1c 47 c5 03 c7 ba 74 62  |..F......G....tb|
	// 00000010  19 31 76 8e fd dd 07 70  85 7f c1 e2 0d a8 30 0c  |.1v....p......0.|
	// 00000020  33 02 5b 02 7c 6b 4f 5b  0d 2d 22 2b 9d 15 7a 8f  |3.[.|kO[.-"+..z.|
	// 00000030  8d 3c fe f8 50 2f b6 41  ab 3d 21 2e 6f 37 a4 0e  |.<..P/.A.=!.o7..|
	// Signature verified against correct message.
	// Verifying against wrong message: invalid signature
}

// This example demonstrates how to create unlinkable anonymity-set signatures,
// and to verify them,
// using a small anonymity set containing three public keys.
func ExampleSign_anonSet() {

	// Crypto setup
	suite := edwards25519.NewAES128SHA256Ed25519()
	rand := suite.Cipher([]byte("example"))

	// Create an anonymity set of random "public keys"
	X := make([]kyber.Point, 3)
	for i := range X { // pick random points
		X[i] = suite.Point().Pick(rand)
	}

	// Make just one of them an actual public/private keypair (X[mine],x)
	mine := 1                           // only the signer knows this
	x := suite.Scalar().Pick(rand)      // create a private key x
	X[mine] = suite.Point().Mul(x, nil) // corresponding public key X

	// Generate the signature
	M := []byte("Hello World!") // message we want to sign
	sig := Sign(suite, rand, M, Set(X), nil, mine, x)
	fmt.Print("Signature:\n" + hex.Dump(sig))

	// Verify the signature against the correct message
	tag, err := Verify(suite, M, Set(X), nil, sig)
	if err != nil {
		panic(err.Error())
	}
	if tag == nil || len(tag) != 0 {
		panic("Verify returned wrong tag")
	}
	fmt.Println("Signature verified against correct message.")

	// Verify the signature against the wrong message
	BAD := []byte("Goodbye world!")
	tag, err = Verify(suite, BAD, Set(X), nil, sig)
	if err == nil || tag != nil {
		panic("Signature verified against wrong message!?")
	}
	fmt.Println("Verifying against wrong message: " + err.Error())

	// Output:
	// Signature:
	// 00000000  c9 8b b1 89 56 89 59 6a  ea 78 92 57 aa d0 4e cf  |....V.Yj.x.W..N.|
	// 00000010  aa 0b e4 7a ee 13 38 c0  14 1e 47 17 35 de 87 08  |...z..8...G.5...|
	// 00000020  31 68 8d ca 3f 6a 85 a1  0d f1 cf 9d 21 05 83 f2  |1h..?j......!...|
	// 00000030  35 63 b0 65 a8 50 a5 ee  ec 95 f8 fd 78 de 73 08  |5c.e.P......x.s.|
	// 00000040  87 d0 93 55 76 c9 f9 54  5f 35 82 2f c4 c9 99 db  |...Uv..T_5./....|
	// 00000050  58 8e 93 13 ce d5 c1 4d  97 e9 57 d8 5d b2 f9 01  |X......M..W.]...|
	// 00000060  ee f3 b2 f4 06 e4 98 a7  24 2f 51 b8 13 b4 b5 69  |........$/Q....i|
	// 00000070  94 ad 33 b9 c4 e3 95 8b  7f 18 6d 1e f1 07 3e 0d  |..3.......m...>.|
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
	suite := edwards25519.NewAES128SHA256Ed25519()
	rand := suite.Cipher([]byte("example"))

	// Create an anonymity set of random "public keys"
	X := make([]kyber.Point, 3)
	for i := range X { // pick random points
		X[i] = suite.Point().Pick(rand)
	}

	// Make two actual public/private keypairs (X[mine],x)
	mine1 := 1 // only the signer knows this
	mine2 := 2
	x1 := suite.Scalar().Pick(rand) // create a private key x
	x2 := suite.Scalar().Pick(rand)
	X[mine1] = suite.Point().Mul(x1, nil) // corresponding public key X
	X[mine2] = suite.Point().Mul(x2, nil)

	// Generate two signatures using x1 and two using x2
	M := []byte("Hello World!")     // message we want to sign
	S := []byte("My Linkage Scope") // scope for linkage tags
	var sig [4][]byte
	sig[0] = Sign(suite, rand, M, Set(X), S, mine1, x1)
	sig[1] = Sign(suite, rand, M, Set(X), S, mine1, x1)
	sig[2] = Sign(suite, rand, M, Set(X), S, mine2, x2)
	sig[3] = Sign(suite, rand, M, Set(X), S, mine2, x2)
	for i := range sig {
		fmt.Printf("Signature %d:\n%s", i, hex.Dump(sig[i]))
	}

	// Verify the signatures against the correct message
	var tag [4][]byte
	for i := range sig {
		goodtag, err := Verify(suite, M, Set(X), S, sig[i])
		if err != nil {
			panic(err.Error())
		}
		tag[i] = goodtag
		if tag[i] == nil || len(tag[i]) != suite.PointLen() {
			panic("Verify returned invalid tag")
		}
		fmt.Printf("Sig%d tag: %s\n", i,
			hex.EncodeToString(tag[i]))

		// Verify the signature against the wrong message
		BAD := []byte("Goodbye world!")
		badtag, err := Verify(suite, BAD, Set(X), S, sig[i])
		if err == nil || badtag != nil {
			panic("Signature verified against wrong message!?")
		}
	}
	if !bytes.Equal(tag[0], tag[1]) || !bytes.Equal(tag[2], tag[3]) ||
		bytes.Equal(tag[0], tag[2]) {
		panic("tags aren't coming out right!")
	}

	// Output:
	// Signature 0:
	// 00000000  7b 6c 2a 43 0b 3b 8e 03  f1 c5 ee 59 62 ad d1 3b  |{l*C.;.....Yb..;|
	// 00000010  d3 81 85 62 db 7e 23 9e  e6 91 ee e0 29 9c bd 00  |...b.~#.....)...|
	// 00000020  35 e7 59 fa 2b 41 20 f8  b6 48 43 62 91 f1 c6 99  |5.Y.+A ..HCb....|
	// 00000030  0e 64 9c 2c 06 fe 84 75  4f ca 03 7f 28 b5 6d 0c  |.d.,...uO...(.m.|
	// 00000040  6e 01 1f 08 c5 f0 5e 25  59 97 a9 9e f2 bd a3 4a  |n.....^%Y......J|
	// 00000050  26 8b 2b 20 63 d2 1f e6  f3 80 5b 4a e7 3f 79 0d  |&.+ c.....[J.?y.|
	// 00000060  31 68 8d ca 3f 6a 85 a1  0d f1 cf 9d 21 05 83 f2  |1h..?j......!...|
	// 00000070  35 63 b0 65 a8 50 a5 ee  ec 95 f8 fd 78 de 73 08  |5c.e.P......x.s.|
	// 00000080  25 81 72 e4 49 1b a2 c7  a0 13 66 e6 25 d1 bf dd  |%.r.I.....f.%...|
	// 00000090  34 8a 42 89 b0 83 78 32  b6 ed 10 7c 86 0c 9e 0d  |4.B...x2...|....|
	// Signature 1:
	// 00000000  36 b8 30 60 28 60 01 af  22 59 a2 19 76 f1 12 d6  |6.0`(`.."Y..v...|
	// 00000010  af 03 7c 3d 59 68 f4 3c  86 ed 00 7d 40 21 10 0a  |..|=Yh.<...}@!..|
	// 00000020  67 70 bb 6e d1 b1 c6 16  2c ea b7 59 4f 1d 13 f8  |gp.n....,..YO...|
	// 00000030  87 6f a8 74 f6 a8 f2 35  38 0a 67 e4 a9 26 3e 02  |.o.t...58.g..&>.|
	// 00000040  b6 be dd 7e ea f9 e5 e3  d6 2b 6d 6f dd f5 2d 18  |...~.....+mo..-.|
	// 00000050  1e f4 65 ec ad ce e6 cc  ee a4 30 28 91 0b 72 0c  |..e.......0(..r.|
	// 00000060  fe e8 5c 0c 56 18 63 19  e2 f4 4d 6f b4 5d 1c ea  |..\.V.c...Mo.]..|
	// 00000070  5d 37 8b 13 9b 2c 7f c6  64 21 5e 38 93 27 f4 06  |]7...,..d!^8.'..|
	// 00000080  25 81 72 e4 49 1b a2 c7  a0 13 66 e6 25 d1 bf dd  |%.r.I.....f.%...|
	// 00000090  34 8a 42 89 b0 83 78 32  b6 ed 10 7c 86 0c 9e 0d  |4.B...x2...|....|
	// Signature 2:
	// 00000000  77 a7 4c e5 da 22 80 6a  51 07 3a 9a 7a e8 02 84  |w.L..".jQ.:.z...|
	// 00000010  85 c2 d2 3e 52 cc 6a 37  dc f3 3c 7c 91 e6 6f 01  |...>R.j7..<|..o.|
	// 00000020  58 c9 50 76 f9 f8 e5 7b  54 fc dd 89 5c 64 54 7c  |X.Pv...{T...\dT||
	// 00000030  52 21 d9 30 0d b5 9b 13  3d 4b 5e d4 c4 fe f5 06  |R!.0....=K^.....|
	// 00000040  1e 91 e3 7b 4b 6a 9d f8  82 d3 42 19 1a bf 94 80  |...{Kj....B.....|
	// 00000050  33 92 bd 73 47 09 71 38  0f 06 23 d7 9e 8e 96 0b  |3..sG.q8..#.....|
	// 00000060  b3 c7 76 86 40 32 12 b6  a3 81 82 43 27 f8 4b dc  |..v.@2.....C'.K.|
	// 00000070  cd 47 ae 3c b2 bb ff 51  08 4f f1 08 4f d5 44 0c  |.G.<...Q.O..O.D.|
	// 00000080  02 fa 87 10 32 09 17 e2  09 dd d9 95 44 9f 34 01  |....2.......D.4.|
	// 00000090  8d 1a 80 fa c9 c6 fe 5d  29 92 b2 7e 26 7b 11 2c  |.......])..~&{.,|
	// Signature 3:
	// 00000000  87 2b 07 82 15 0a c7 0c  f7 8c 75 cf ac 89 8c 6d  |.+........u....m|
	// 00000010  dd 5e 96 f7 d4 e0 8d 5c  91 11 ad fe 0d 7b 1c 01  |.^.....\.....{..|
	// 00000020  45 a7 41 99 c3 ef 1f db  80 40 47 1a 19 b1 57 cd  |E.A......@G...W.|
	// 00000030  19 df c9 a2 db 38 bb 14  b6 1d 64 3f 3e e2 36 03  |.....8....d?>.6.|
	// 00000040  55 66 b1 9c a7 5b ca 61  ba c8 c6 5c 9e 04 80 85  |Uf...[.a...\....|
	// 00000050  e4 64 7f 81 e7 38 6d 97  92 83 65 02 e7 a4 81 05  |.d...8m...e.....|
	// 00000060  0a b6 73 96 e2 f4 78 53  52 75 9c a5 20 d3 d6 8f  |..s...xSRu.. ...|
	// 00000070  b4 36 54 e1 67 9f 79 4e  a2 c7 51 17 62 62 65 08  |.6T.g.yN..Q.bbe.|
	// 00000080  02 fa 87 10 32 09 17 e2  09 dd d9 95 44 9f 34 01  |....2.......D.4.|
	// 00000090  8d 1a 80 fa c9 c6 fe 5d  29 92 b2 7e 26 7b 11 2c  |.......])..~&{.,|
	// Sig0 tag: 258172e4491ba2c7a01366e625d1bfdd348a4289b0837832b6ed107c860c9e0d
	// Sig1 tag: 258172e4491ba2c7a01366e625d1bfdd348a4289b0837832b6ed107c860c9e0d
	// Sig2 tag: 02fa8710320917e209ddd995449f34018d1a80fac9c6fe5d2992b27e267b112c
	// Sig3 tag: 02fa8710320917e209ddd995449f34018d1a80fac9c6fe5d2992b27e267b112c
}

var benchMessage = []byte("Hello World!")

var benchPubEd25519, benchPriEd25519 = benchGenKeysEd25519(100)
var benchSig1Ed25519 = benchGenSigEd25519(1)
var benchSig10Ed25519 = benchGenSigEd25519(10)
var benchSig100Ed25519 = benchGenSigEd25519(100)

func benchGenKeys(g kyber.Group,
	nkeys int) ([]kyber.Point, kyber.Scalar) {

	rand := random.Stream

	// Create an anonymity set of random "public keys"
	X := make([]kyber.Point, nkeys)
	for i := range X { // pick random points
		X[i] = g.Point().Pick(rand)
	}

	// Make just one of them an actual public/private keypair (X[mine],x)
	x := g.Scalar().Pick(rand)
	X[0] = g.Point().Mul(x, nil)

	return X, x
}

func benchGenKeysEd25519(nkeys int) ([]kyber.Point, kyber.Scalar) {
	return benchGenKeys(edwards25519.NewAES128SHA256Ed25519(), nkeys)
}
func benchGenSigEd25519(nkeys int) []byte {
	suite := edwards25519.NewAES128SHA256Ed25519()
	rand := suite.Cipher([]byte("example"))
	return Sign(suite, rand, benchMessage,
		Set(benchPubEd25519[:nkeys]), nil,
		0, benchPriEd25519)
}

func benchSign(suite Suite, pub []kyber.Point, pri kyber.Scalar,
	niter int) {
	rand := suite.XOF([]byte("example"))
	for i := 0; i < niter; i++ {
		Sign(suite, rand, benchMessage, Set(pub), nil, 0, pri)
	}
}

func benchVerify(suite Suite, pub []kyber.Point,
	sig []byte, niter int) {
	for i := 0; i < niter; i++ {
		tag, err := Verify(suite, benchMessage, Set(pub), nil, sig)
		if tag == nil || err != nil {
			panic("benchVerify failed")
		}
	}
}

func BenchmarkSign1Ed25519(b *testing.B) {
	benchSign(edwards25519.NewAES128SHA256Ed25519(),
		benchPubEd25519[:1], benchPriEd25519, b.N)
}
func BenchmarkSign10Ed25519(b *testing.B) {
	benchSign(edwards25519.NewAES128SHA256Ed25519(),
		benchPubEd25519[:10], benchPriEd25519, b.N)
}
func BenchmarkSign100Ed25519(b *testing.B) {
	benchSign(edwards25519.NewAES128SHA256Ed25519(),
		benchPubEd25519[:100], benchPriEd25519, b.N)
}

func BenchmarkVerify1Ed25519(b *testing.B) {
	benchVerify(edwards25519.NewAES128SHA256Ed25519(),
		benchPubEd25519[:1], benchSig1Ed25519, b.N)
}
func BenchmarkVerify10Ed25519(b *testing.B) {
	benchVerify(edwards25519.NewAES128SHA256Ed25519(),
		benchPubEd25519[:10], benchSig10Ed25519, b.N)
}
func BenchmarkVerify100Ed25519(b *testing.B) {
	benchVerify(edwards25519.NewAES128SHA256Ed25519(),
		benchPubEd25519[:100], benchSig100Ed25519, b.N)
}
