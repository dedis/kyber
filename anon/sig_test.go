package anon

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"github.com/dedis/crypto/abstract"
	"github.com/dedis/crypto/suite"
)

// This example demonstrates signing and signature verification
// using a trivial "anonymity set" of size 1, i.e., no anonymity.
// In this special case the signing scheme devolves to
// producing traditional ElGamal signatures:
// the resulting signatures are exactly the same length
// and represent essentially the same computational cost.
func ExampleSign_1() {

	// Crypto setup
	suite := suite.Default(nil)
	rand := suite.Cipher([]byte("example"))

	// Create a public/private keypair (X[mine],x)
	X := make([]abstract.Point, 1)
	mine := 0                          // which public key is mine
	x := suite.Scalar().Random(rand)   // create a private key x
	X[mine] = suite.Point().BaseMul(x) // corresponding public key X

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
	// 00000000  0a 17 04 6e 1b 42 ca 0a  30 6d 1e 45 27 cb 90 ca  |...n.B..0m.E'...|
	// 00000010  2a a4 5c 4e 50 b2 ae fc  1b b8 bf 00 2e 55 dc 35  |*.\NP........U.5|
	// 00000020  0a 2a ca 87 50 a7 1e 12  a9 d2 8a 7b 64 b8 39 17  |.*..P......{d.9.|
	// 00000030  a0 41 ff 5f 9c d9 a3 0b  b8 0b 67 41 fb 25 ff 5b  |.A._......gA.%.[|
	// Signature verified against correct message.
	// Verifying against wrong message: invalid signature
}

// This example demonstrates how to create unlinkable anonymity-set signatures,
// and to verify them,
// using a small anonymity set containing three public keys.
func ExampleSign_anonSet() {

	// Crypto setup
	suite := suite.Default(nil)
	rand := suite.Cipher([]byte("example"))

	// Create an anonymity set of random "public keys"
	X := make([]abstract.Point, 3)
	for i := range X { // pick random points
		X[i] = suite.Point().Random(rand)
	}

	// Make just one of them an actual public/private keypair (X[mine],x)
	mine := 1                          // only the signer knows this
	x := suite.Scalar().Random(rand)   // create a private key x
	X[mine] = suite.Point().BaseMul(x) // corresponding public key X

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
	// 00000000  0a 3a e6 85 6f 50 bb ec  9f ab 25 45 2e cc 64 f9  |.:..oP....%E..d.|
	// 00000010  51 72 e8 52 0f c7 11 01  3c bc 8f ef b4 41 1a d6  |Qr.R....<....A..|
	// 00000020  00 d1 38 cf b7 95 b6 28  8c da b2 3b f3 61 43 3b  |..8....(...;.aC;|
	// 00000030  21 db 9b 5a d2 e1 24 87  8a 83 be ef 98 ef 92 99  |!..Z..$.........|
	// 00000040  04 f1 da b0 07 4b b5 62  e8 c3 28 52 5b ca 9a 06  |.....K.b..(R[...|
	// 00000050  58 fa a2 cf 2f 2d a4 8e  a6 89 0c 6c aa 06 8f 54  |X.../-.....l...T|
	// 00000060  0a c2 a9 d2 4d 3c 76 6e  79 bf a6 eb 45 2d ec 55  |....M<vny...E-.U|
	// 00000070  b6 24 d3 90 6a 06 36 d2  16 c4 3a 09 62 29 56 34  |.$..j.6...:.b)V4|
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
	suite := suite.Default(nil)
	rand := suite.Cipher([]byte("example"))

	// Create an anonymity set of random "public keys"
	X := make([]abstract.Point, 3)
	for i := range X { // pick random points
		X[i] = suite.Point().Random(rand)
	}

	// Make two actual public/private keypairs (X[mine],x)
	mine1 := 1 // only the signer knows this
	mine2 := 2
	x1 := suite.Scalar().Random(rand) // create a private key x
	x2 := suite.Scalar().Random(rand)
	X[mine1] = suite.Point().BaseMul(x1) // corresponding public key X
	X[mine2] = suite.Point().BaseMul(x2)

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
	// 00000000  02 5c c4 64 1b 28 7f 06  77 cc 91 47 c2 6f f2 30  |.\.d.(..w..G.o.0|
	// 00000010  d5 76 dc a3 b6 d2 b5 b0  06 77 ac 81 33 2b e2 2e  |.v.......w..3+..|
	// 00000020  05 bf ec 1c 58 a5 35 c4  e8 d1 77 32 1b 71 17 62  |....X.5...w2.q.b|
	// 00000030  dd ed 45 97 f0 5c fc 69  ad e7 21 ec 2e a6 12 17  |..E..\.i..!.....|
	// 00000040  0c 8c 76 33 49 9f da 30  3d fc 66 ab d1 29 f0 49  |..v3I..0=.f..).I|
	// 00000050  e7 6b 1e 19 3c b1 b2 f7  0a 1f 18 65 e7 7c 3e 66  |.k..<......e.|>f|
	// 00000060  00 d1 38 cf b7 95 b6 28  8c da b2 3b f3 61 43 3b  |..8....(...;.aC;|
	// 00000070  21 db 9b 5a d2 e1 24 87  8a 83 be ef 98 ef 92 99  |!..Z..$.........|
	// 00000080  0e 9d 2b f8 b7 fa f7 92  97 14 de d3 81 b6 1e dc  |..+.............|
	// 00000090  1a 7b 07 59 50 cf 83 4c  d8 a1 8d 00 0a e6 f8 27  |.{.YP..L.......'|
	// Signature 1:
	// 00000000  00 2e 2f 2d be fc 14 da  97 15 0e f6 49 54 eb 8a  |../-........IT..|
	// 00000010  54 59 f4 d3 f9 f9 ec 32  54 b7 57 4d 16 77 0a e3  |TY.....2T.WM.w..|
	// 00000020  03 b7 ab 19 65 f7 f6 df  dd 44 cb 63 8a e6 96 88  |....e....D.c....|
	// 00000030  fc 7c 80 49 be 6d af b3  45 62 15 72 cc 6d ef f3  |.|.I.m..Eb.r.m..|
	// 00000040  07 5d 36 c9 59 f7 90 f1  a0 a1 bf da 45 cd ae 2c  |.]6.Y.......E..,|
	// 00000050  29 ae b4 76 b1 04 b7 75  87 8e f1 a0 00 79 f0 c8  |)..v...u.....y..|
	// 00000060  09 5a e3 24 24 58 aa 9e  8f d6 64 73 75 9b fa 22  |.Z.$$X....dsu.."|
	// 00000070  08 8e c8 08 3a da fd 1f  31 84 e5 de a1 79 42 f5  |....:...1....yB.|
	// 00000080  0e 9d 2b f8 b7 fa f7 92  97 14 de d3 81 b6 1e dc  |..+.............|
	// 00000090  1a 7b 07 59 50 cf 83 4c  d8 a1 8d 00 0a e6 f8 27  |.{.YP..L.......'|
	// Signature 2:
	// 00000000  01 c8 5e fa 49 ab e1 0d  ce 6d 92 71 fd 0c 8c d5  |..^.I....m.q....|
	// 00000010  d5 c3 e0 2c c0 50 fa a1  09 ea e6 76 25 b3 0d 7c  |...,.P.....v%..||
	// 00000020  0a e2 ec 38 78 81 db 7a  5c b8 53 da 28 59 26 88  |...8x..z\.S.(Y&.|
	// 00000030  06 fb 02 1d 76 3b d1 fb  fd 66 c5 4e 69 09 77 be  |....v;...f.Ni.w.|
	// 00000040  01 79 38 a8 50 e5 5b b3  cc 3a 41 88 55 dc a8 9a  |.y8.P.[..:A.U...|
	// 00000050  6b 8b c0 3e e1 d1 cb ef  19 20 cd 74 9e 82 1d c3  |k..>..... .t....|
	// 00000060  00 be 55 33 7d fb e2 6b  97 7c ac 10 66 4b a5 9d  |..U3}..k.|..fK..|
	// 00000070  20 6d 4b c5 3e ac d3 f9  e0 16 a9 c5 b3 b8 30 4a  | mK.>.........0J|
	// 00000080  fc 35 63 34 e3 d2 4d ca  71 07 03 54 e8 17 ef 4c  |.5c4..M.q..T...L|
	// 00000090  4b 3f 65 49 e9 ef b9 fe  42 b8 70 26 11 55 5d 50  |K?eI....B.p&.U]P|
	// Signature 3:
	// 00000000  06 1b 72 24 c5 e0 b5 04  66 d7 21 19 fd 00 2d 4c  |..r$....f.!...-L|
	// 00000010  15 ba 33 7d d3 e0 d8 8e  db a2 5a 38 d9 b6 7d f4  |..3}......Z8..}.|
	// 00000020  01 e7 85 0d 41 60 ff e2  5a a1 b9 3c 73 f3 53 c7  |....A`..Z..<s.S.|
	// 00000030  46 be a9 e1 78 dc 7f 8c  59 af 16 a6 9d 3c a9 57  |F...x...Y....<.W|
	// 00000040  04 57 0e 22 94 a9 d7 0e  bc 69 7e 31 13 02 49 c0  |.W.".....i~1..I.|
	// 00000050  7b c7 a4 da 3d f1 96 16  47 02 7f 36 ea 12 05 a2  |{...=...G..6....|
	// 00000060  06 e2 00 de 28 18 d0 39  5b 60 f8 76 0c 93 8a 63  |....(..9[`.v...c|
	// 00000070  40 f8 61 cf 4e 0c f7 fd  c1 91 bc 00 c9 cc 88 c6  |@.a.N...........|
	// 00000080  fc 35 63 34 e3 d2 4d ca  71 07 03 54 e8 17 ef 4c  |.5c4..M.q..T...L|
	// 00000090  4b 3f 65 49 e9 ef b9 fe  42 b8 70 26 11 55 5d 50  |K?eI....B.p&.U]P|
	// Sig0 tag: 0e9d2bf8b7faf7929714ded381b61edc1a7b075950cf834cd8a18d000ae6f827
	// Sig1 tag: 0e9d2bf8b7faf7929714ded381b61edc1a7b075950cf834cd8a18d000ae6f827
	// Sig2 tag: fc356334e3d24dca71070354e817ef4c4b3f6549e9efb9fe42b8702611555d50
	// Sig3 tag: fc356334e3d24dca71070354e817ef4c4b3f6549e9efb9fe42b8702611555d50
}

/*
var benchMessage = []byte("Hello World!")

var benchPubOpenSSL, benchPriOpenSSL = benchGenKeysOpenSSL(100)
var benchSig1OpenSSL = benchGenSigOpenSSL(1)
var benchSig10OpenSSL = benchGenSigOpenSSL(10)
var benchSig100OpenSSL = benchGenSigOpenSSL(100)

var benchPubEd25519, benchPriEd25519 = benchGenKeysEd25519(100)
var benchSig1Ed25519 = benchGenSigEd25519(1)
var benchSig10Ed25519 = benchGenSigEd25519(10)
var benchSig100Ed25519 = benchGenSigEd25519(100)

func benchGenKeys(suite abstract.Suite,
	nkeys int) ([]abstract.Point, abstract.Scalar) {

	rand := random.Fresh()

	// Create an anonymity set of random "public keys"
	X := make([]abstract.Point, nkeys)
	for i := range X { // pick random points
		X[i] = suite.Point().Random(rand)
	}

	// Make just one of them an actual public/private keypair (X[mine],x)
	x := suite.Scalar().Pick(rand)
	X[0] = suite.Point().BaseMul(x)

	return X, x
}

func benchGenKeysOpenSSL(nkeys int) ([]abstract.Point, abstract.Scalar) {
	return benchGenKeys(openssl.NewAES128SHA256P256(), nkeys)
}
func benchGenSigOpenSSL(nkeys int) []byte {
	suite := nist.NewAES128SHA256P256()
	rand := suite.Cipher([]byte("example"))
	return Sign(suite, rand, benchMessage,
		Set(benchPubOpenSSL[:nkeys]), nil,
		0, benchPriOpenSSL)
}

func benchGenKeysEd25519(nkeys int) ([]abstract.Point, abstract.Scalar) {
	return benchGenKeys(edwards.NewAES128SHA256Ed25519(false), nkeys)
}
func benchGenSigEd25519(nkeys int) []byte {
	suite := edwards.NewAES128SHA256Ed25519(false)
	rand := suite.Cipher([]byte("example"))
	return Sign(suite, rand, benchMessage,
		Set(benchPubEd25519[:nkeys]), nil,
		0, benchPriEd25519)
}

func benchSign(suite abstract.Suite, pub []abstract.Point, pri abstract.Scalar,
	niter int) {
	rand := suite.Cipher([]byte("example"))
	for i := 0; i < niter; i++ {
		Sign(suite, rand, benchMessage, Set(pub), nil, 0, pri)
	}
}

func benchVerify(suite abstract.Suite, pub []abstract.Point,
	sig []byte, niter int) {
	for i := 0; i < niter; i++ {
		tag, err := Verify(suite, benchMessage, Set(pub), nil, sig)
		if tag == nil || err != nil {
			panic("benchVerify failed")
		}
	}
}

func BenchmarkSign1OpenSSL(b *testing.B) {
	benchSign(nist.NewAES128SHA256P256(),
		benchPubOpenSSL[:1], benchPriOpenSSL, b.N)
}
func BenchmarkSign10OpenSSL(b *testing.B) {
	benchSign(nist.NewAES128SHA256P256(),
		benchPubOpenSSL[:10], benchPriOpenSSL, b.N)
}
func BenchmarkSign100OpenSSL(b *testing.B) {
	benchSign(nist.NewAES128SHA256P256(),
		benchPubOpenSSL[:100], benchPriOpenSSL, b.N)
}

func BenchmarkVerify1OpenSSL(b *testing.B) {
	benchVerify(nist.NewAES128SHA256P256(),
		benchPubOpenSSL[:1], benchSig1OpenSSL, b.N)
}
func BenchmarkVerify10OpenSSL(b *testing.B) {
	benchVerify(nist.NewAES128SHA256P256(),
		benchPubOpenSSL[:10], benchSig10OpenSSL, b.N)
}
func BenchmarkVerify100OpenSSL(b *testing.B) {
	benchVerify(nist.NewAES128SHA256P256(),
		benchPubOpenSSL[:100], benchSig100OpenSSL, b.N)
}

func BenchmarkSign1Ed25519(b *testing.B) {
	benchSign(edwards.NewAES128SHA256Ed25519(false),
		benchPubEd25519[:1], benchPriEd25519, b.N)
}
func BenchmarkSign10Ed25519(b *testing.B) {
	benchSign(edwards.NewAES128SHA256Ed25519(false),
		benchPubEd25519[:10], benchPriEd25519, b.N)
}
func BenchmarkSign100Ed25519(b *testing.B) {
	benchSign(edwards.NewAES128SHA256Ed25519(false),
		benchPubEd25519[:100], benchPriEd25519, b.N)
}

func BenchmarkVerify1Ed25519(b *testing.B) {
	benchVerify(edwards.NewAES128SHA256Ed25519(false),
		benchPubEd25519[:1], benchSig1Ed25519, b.N)
}
func BenchmarkVerify10Ed25519(b *testing.B) {
	benchVerify(edwards.NewAES128SHA256Ed25519(false),
		benchPubEd25519[:10], benchSig10Ed25519, b.N)
}
func BenchmarkVerify100Ed25519(b *testing.B) {
	benchVerify(edwards.NewAES128SHA256Ed25519(false),
		benchPubEd25519[:100], benchSig100Ed25519, b.N)
}
*/
