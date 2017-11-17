package anon

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/dedis/kyber"
	"github.com/dedis/kyber/group/edwards25519"
	"github.com/dedis/kyber/util/random"
	"github.com/dedis/kyber/xof"
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
		fmt.Println(err.Error())
		return
	}
	if tag == nil || len(tag) != 0 {
		fmt.Println("Verify returned wrong tag")
		return
	}
	fmt.Println("Signature verified against correct message.")

	// Verify the signature against the wrong message
	BAD := []byte("Goodbye world!")
	tag, err = Verify(suite, BAD, Set(X), nil, sig)
	if err == nil || tag != nil {
		fmt.Println("Signature verified against wrong message!?")
		return
	}
	fmt.Println("Verifying against wrong message: " + err.Error())

	// Output:
	// Signature:
	// 00000000  53 3f 7d 30 a9 4d e5 83  c5 19 da 6e df e5 bf e1  |S?}0.M.....n....|
	// 00000010  db e7 7a 9e 4b 14 46 69  18 79 e9 69 b5 a0 47 0e  |..z.K.Fi.y.i..G.|
	// 00000020  30 ea 70 24 34 68 58 f9  86 de 5a 32 8f c6 07 de  |0.p$4hX...Z2....|
	// 00000030  5e 58 32 6a 20 8b 85 11  bc 18 34 52 2d e4 03 0f  |^X2j .....4R-...|
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
		fmt.Println(err.Error())
		return
	}
	if tag == nil || len(tag) != 0 {
		fmt.Println("Verify returned wrong tag")
		return
	}
	fmt.Println("Signature verified against correct message.")

	// Verify the signature against the wrong message
	BAD := []byte("Goodbye world!")
	tag, err = Verify(suite, BAD, Set(X), nil, sig)
	if err == nil || tag != nil {
		fmt.Println("Signature verified against wrong message!?")
	}
	fmt.Println("Verifying against wrong message: " + err.Error())

	// Output:
	// Signature:
	// 00000000  6b 56 ec 4e 1e 06 13 7a  18 0d 8f e9 7e ac a5 3d  |kV.N...z....~..=|
	// 00000010  4c ec cc e3 94 52 86 1d  de f7 0e 44 67 3b 9f 0c  |L....R.....Dg;..|
	// 00000020  31 68 8d ca 3f 6a 85 a1  0d f1 cf 9d 21 05 83 f2  |1h..?j......!...|
	// 00000030  35 63 b0 65 a8 50 a5 ee  ec 95 f8 fd 78 de 73 08  |5c.e.P......x.s.|
	// 00000040  dd 5f aa c9 e5 2f df 2f  59 a9 2f 79 a3 4a 77 7c  |._..././Y./y.Jw||
	// 00000050  dd 95 05 f2 c3 a7 8b 53  25 aa d0 39 b3 9f 4c 0c  |.......S%..9..L.|
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
			fmt.Println(err.Error())
			return
		}
		tag[i] = goodtag
		if tag[i] == nil || len(tag[i]) != suite.PointLen() {
			fmt.Println("Verify returned invalid tag")
			return
		}
		fmt.Printf("Sig%d tag: %s\n", i,
			hex.EncodeToString(tag[i]))

		// Verify the signature against the wrong message
		BAD := []byte("Goodbye world!")
		badtag, err := Verify(suite, BAD, Set(X), S, sig[i])
		if err == nil || badtag != nil {
			fmt.Println("Signature verified against wrong message!?")
			return
		}
	}
	if !bytes.Equal(tag[0], tag[1]) || !bytes.Equal(tag[2], tag[3]) ||
		bytes.Equal(tag[0], tag[2]) {
		fmt.Println("tags aren't coming out right!")
		return
	}

	// Output:
	// Signature 0:
	// 00000000  95 2b 9e 8f 71 49 f1 88  d5 77 99 67 bb 1f c4 ef  |.+..qI...w.g....|
	// 00000010  d9 e2 d1 69 fe ac ce 53  5f d2 7f 42 e3 54 94 06  |...i...S_..B.T..|
	// 00000020  35 e7 59 fa 2b 41 20 f8  b6 48 43 62 91 f1 c6 99  |5.Y.+A ..HCb....|
	// 00000030  0e 64 9c 2c 06 fe 84 75  4f ca 03 7f 28 b5 6d 0c  |.d.,...uO...(.m.|
	// 00000040  3d 07 10 3f 9d 42 26 40  c6 da 8e 48 63 a2 7f 96  |=..?.B&@...Hc...|
	// 00000050  5e 3b 00 2c 82 44 30 fc  0e 69 02 1b 0b 40 45 01  |^;.,.D0..i...@E.|
	// 00000060  31 68 8d ca 3f 6a 85 a1  0d f1 cf 9d 21 05 83 f2  |1h..?j......!...|
	// 00000070  35 63 b0 65 a8 50 a5 ee  ec 95 f8 fd 78 de 73 08  |5c.e.P......x.s.|
	// 00000080  5d 03 34 02 cb 1b 4c c0  5d ed 55 38 7a f7 2f 88  |].4...L.].U8z./.|
	// 00000090  ef 88 d4 4a 39 79 af ef  d1 6c c6 3d 47 02 33 f5  |...J9y...l.=G.3.|
	// Signature 1:
	// 00000000  89 8d e9 a1 d0 f6 34 83  93 ae 6b f2 d0 36 1e 36  |......4...k..6.6|
	// 00000010  10 92 7e 47 2c 5e 50 1d  09 a8 fd 43 7b ff 9a 00  |..~G,^P....C{...|
	// 00000020  67 70 bb 6e d1 b1 c6 16  2c ea b7 59 4f 1d 13 f8  |gp.n....,..YO...|
	// 00000030  87 6f a8 74 f6 a8 f2 35  38 0a 67 e4 a9 26 3e 02  |.o.t...58.g..&>.|
	// 00000040  43 be c7 5b 32 13 08 7c  68 43 57 55 c2 29 6b 7d  |C..[2..|hCWU.)k}|
	// 00000050  90 9d 3f f0 89 1c 97 87  27 d9 d3 b3 92 f2 b0 00  |..?.....'.......|
	// 00000060  fe e8 5c 0c 56 18 63 19  e2 f4 4d 6f b4 5d 1c ea  |..\.V.c...Mo.]..|
	// 00000070  5d 37 8b 13 9b 2c 7f c6  64 21 5e 38 93 27 f4 06  |]7...,..d!^8.'..|
	// 00000080  5d 03 34 02 cb 1b 4c c0  5d ed 55 38 7a f7 2f 88  |].4...L.].U8z./.|
	// 00000090  ef 88 d4 4a 39 79 af ef  d1 6c c6 3d 47 02 33 f5  |...J9y...l.=G.3.|
	// Signature 2:
	// 00000000  d3 4a 5d 96 11 5b b6 a5  ae fb fd b3 88 c9 20 12  |.J]..[........ .|
	// 00000010  1e b4 9c af aa 91 91 0d  3d 0c 8e b4 c5 a7 4e 08  |........=.....N.|
	// 00000020  58 c9 50 76 f9 f8 e5 7b  54 fc dd 89 5c 64 54 7c  |X.Pv...{T...\dT||
	// 00000030  52 21 d9 30 0d b5 9b 13  3d 4b 5e d4 c4 fe f5 06  |R!.0....=K^.....|
	// 00000040  1e 91 e3 7b 4b 6a 9d f8  82 d3 42 19 1a bf 94 80  |...{Kj....B.....|
	// 00000050  33 92 bd 73 47 09 71 38  0f 06 23 d7 9e 8e 96 0b  |3..sG.q8..#.....|
	// 00000060  a7 7d 5f 61 7e 2a cb 42  40 c2 79 28 9d ad 53 d3  |.}_a~*.B@.y(..S.|
	// 00000070  e6 ab bc 81 f1 cc 99 19  d8 d6 c0 92 c7 61 96 01  |.............a..|
	// 00000080  a7 0a 12 aa ff ee 46 68  09 2a 20 da 13 70 e2 d4  |......Fh.* ..p..|
	// 00000090  3a f6 be a1 23 27 d6 a8  ae 34 b0 69 a1 a9 a7 d1  |:...#'...4.i....|
	// Signature 3:
	// 00000000  f1 62 96 b8 45 5f c8 52  bc 4f a0 70 4d 41 c6 b3  |.b..E_.R.O.pMA..|
	// 00000010  06 47 7a 0e 7a b8 70 a4  c9 71 05 b0 ad 82 1b 09  |.Gz.z.p..q......|
	// 00000020  45 a7 41 99 c3 ef 1f db  80 40 47 1a 19 b1 57 cd  |E.A......@G...W.|
	// 00000030  19 df c9 a2 db 38 bb 14  b6 1d 64 3f 3e e2 36 03  |.....8....d?>.6.|
	// 00000040  55 66 b1 9c a7 5b ca 61  ba c8 c6 5c 9e 04 80 85  |Uf...[.a...\....|
	// 00000050  e4 64 7f 81 e7 38 6d 97  92 83 65 02 e7 a4 81 05  |.d...8m...e.....|
	// 00000060  cc 92 be a2 a8 81 55 12  7d cd 05 0e 9b a9 74 0a  |......U.}.....t.|
	// 00000070  84 4a 47 90 ea f3 31 67  1f b8 ed 9e cb 67 7e 00  |.JG...1g.....g~.|
	// 00000080  a7 0a 12 aa ff ee 46 68  09 2a 20 da 13 70 e2 d4  |......Fh.* ..p..|
	// 00000090  3a f6 be a1 23 27 d6 a8  ae 34 b0 69 a1 a9 a7 d1  |:...#'...4.i....|
	// Sig0 tag: 5d033402cb1b4cc05ded55387af72f88ef88d44a3979afefd16cc63d470233f5
	// Sig1 tag: 5d033402cb1b4cc05ded55387af72f88ef88d44a3979afefd16cc63d470233f5
	// Sig2 tag: a70a12aaffee4668092a20da1370e2d43af6bea12327d6a8ae34b069a1a9a7d1
	// Sig3 tag: a70a12aaffee4668092a20da1370e2d43af6bea12327d6a8ae34b069a1a9a7d1

}

var benchMessage = []byte("Hello World!")

var benchPubOpenSSL, benchPriOpenSSL = benchGenKeysOpenSSL(100)
var benchSig1OpenSSL = benchGenSigOpenSSL(1)
var benchSig10OpenSSL = benchGenSigOpenSSL(10)
var benchSig100OpenSSL = benchGenSigOpenSSL(100)

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

func benchGenKeysOpenSSL(nkeys int) ([]kyber.Point, kyber.Scalar) {
	return benchGenKeys(edwards25519.NewAES128SHA256Ed25519(), nkeys)
}
func benchGenSigOpenSSL(nkeys int) []byte {
	suite := edwards25519.NewAES128SHA256Ed25519()
	rand := suite.Cipher([]byte("example"))
	return Sign(suite, rand, benchMessage,
		Set(benchPubOpenSSL[:nkeys]), nil,
		0, benchPriOpenSSL)
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
	b *testing.B) {
	rand := xof.New()
	rand.Absorb([]byte("example"))
	for i := 0; i < b.N; i++ {
		Sign(suite, rand, benchMessage, Set(pub), nil, 0, pri)
	}
}

func benchVerify(suite Suite, pub []kyber.Point,
	sig []byte, b *testing.B) {
	for i := 0; i < b.N; i++ {
		tag, err := Verify(suite, benchMessage, Set(pub), nil, sig)
		if tag == nil || err != nil {
			b.Fatal("benchVerify failed")
		}
	}
}

func BenchmarkSign1OpenSSL(b *testing.B) {
	benchSign(edwards25519.NewAES128SHA256Ed25519(),
		benchPubOpenSSL[:1], benchPriOpenSSL, b)
}
func BenchmarkSign10OpenSSL(b *testing.B) {
	benchSign(edwards25519.NewAES128SHA256Ed25519(),
		benchPubOpenSSL[:10], benchPriOpenSSL, b)
}
func BenchmarkSign100OpenSSL(b *testing.B) {
	benchSign(edwards25519.NewAES128SHA256Ed25519(),
		benchPubOpenSSL[:100], benchPriOpenSSL, b)
}

func BenchmarkVerify1OpenSSL(b *testing.B) {
	benchVerify(edwards25519.NewAES128SHA256Ed25519(),
		benchPubOpenSSL[:1], benchSig1OpenSSL, b)
}
func BenchmarkVerify10OpenSSL(b *testing.B) {
	benchVerify(edwards25519.NewAES128SHA256Ed25519(),
		benchPubOpenSSL[:10], benchSig10OpenSSL, b)
}
func BenchmarkVerify100OpenSSL(b *testing.B) {
	benchVerify(edwards25519.NewAES128SHA256Ed25519(),
		benchPubOpenSSL[:100], benchSig100OpenSSL, b)
}

func BenchmarkSign1Ed25519(b *testing.B) {
	benchSign(edwards25519.NewAES128SHA256Ed25519(),
		benchPubEd25519[:1], benchPriEd25519, b)
}
func BenchmarkSign10Ed25519(b *testing.B) {
	benchSign(edwards25519.NewAES128SHA256Ed25519(),
		benchPubEd25519[:10], benchPriEd25519, b)
}
func BenchmarkSign100Ed25519(b *testing.B) {
	benchSign(edwards25519.NewAES128SHA256Ed25519(),
		benchPubEd25519[:100], benchPriEd25519, b)
}

func BenchmarkVerify1Ed25519(b *testing.B) {
	benchVerify(edwards25519.NewAES128SHA256Ed25519(),
		benchPubEd25519[:1], benchSig1Ed25519, b)
}
func BenchmarkVerify10Ed25519(b *testing.B) {
	benchVerify(edwards25519.NewAES128SHA256Ed25519(),
		benchPubEd25519[:10], benchSig10Ed25519, b)
}
func BenchmarkVerify100Ed25519(b *testing.B) {
	benchVerify(edwards25519.NewAES128SHA256Ed25519(),
		benchPubEd25519[:100], benchSig100Ed25519, b)
}
