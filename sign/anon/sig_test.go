package anon

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/dedis/crypto"
	"github.com/dedis/crypto/group/edwards25519"
	"github.com/dedis/crypto/group/nist"
	"github.com/dedis/crypto/util/random"
)

// This example demonstrates signing and signature verification
// using a trivial "anonymity set" of size 1, i.e., no anonymity.
// In this special case the signing scheme devolves to
// producing traditional ElGamal signatures:
// the resulting signatures are exactly the same length
// and represent essentially the same computational cost.
func ExampleSign_1() {

	// Crypto setup
	suite := nist.NewAES128SHA256P256()
	rand := suite.Cipher([]byte("example"))

	// Create a public/private keypair (X[mine],x)
	X := make([]crypto.Point, 1)
	mine := 0                           // which public key is mine
	x := suite.Scalar().Pick(rand)      // create a private key x
	X[mine] = suite.Point().Mul(nil, x) // corresponding public key X

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
	// 00000000  0d 3a d5 66 4d cd 8a bc  ee ae 4a 92 12 e7 63 68  |.:.fM.....J...ch|
	// 00000010  c3 61 9f b0 65 ce f1 d9  83 a7 40 4f e0 7b 58 f5  |.a..e.....@O.{X.|
	// 00000020  5c 64 ca 04 eb 33 db a9  75 9b 01 6b 12 01 ae 4e  |\d...3..u..k...N|
	// 00000030  de 7c 6b 53 85 f8 a5 76  ba eb 7e 2e 61 2c a5 e8  |.|kS...v..~.a,..|
	// Signature verified against correct message.
	// Verifying against wrong message: invalid signature
}

// This example demonstrates how to create unlinkable anonymity-set signatures,
// and to verify them,
// using a small anonymity set containing three public keys.
func ExampleSign_anonSet() {

	// Crypto setup
	suite := nist.NewAES128SHA256P256()
	rand := suite.Cipher([]byte("example"))

	// Create an anonymity set of random "public keys"
	X := make([]crypto.Point, 3)
	for i := range X { // pick random points
		X[i], _ = suite.Point().Pick(nil, rand)
	}

	// Make just one of them an actual public/private keypair (X[mine],x)
	mine := 1                           // only the signer knows this
	x := suite.Scalar().Pick(rand)      // create a private key x
	X[mine] = suite.Point().Mul(nil, x) // corresponding public key X

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
	// 00000000  eb 16 0d c9 1e 19 f5 da  f7 9b 77 7d 52 0b f1 82  |..........w}R...|
	// 00000010  4b e3 dd 6c 44 f3 6f fe  c3 c1 1a 6e 1f a8 43 26  |K..lD.o....n..C&|
	// 00000020  63 d3 5a 0e 97 78 e6 74  ce a0 24 34 c1 66 7d af  |c.Z..x.t..$4.f}.|
	// 00000030  32 9e 59 22 f2 9a 67 3c  ea e5 4f 54 6d 3e 07 f1  |2.Y"..g<..OTm>..|
	// 00000040  63 10 77 96 09 a3 c1 e4  85 f8 d9 97 0c 47 dc 73  |c.w..........G.s|
	// 00000050  da 6c d8 11 8a 2e 00 a7  f2 01 45 e0 91 4e 28 d6  |.l........E..N(.|
	// 00000060  b2 b5 3a e1 c8 8c f7 29  8a 13 75 59 98 ea ce f4  |..:....)..uY....|
	// 00000070  6d d5 d0 62 85 51 8e fe  d9 4a 02 1f 35 03 33 d3  |m..b.Q...J..5.3.|
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
	suite := nist.NewAES128SHA256P256()
	rand := suite.Cipher([]byte("example"))

	// Create an anonymity set of random "public keys"
	X := make([]crypto.Point, 3)
	for i := range X { // pick random points
		X[i], _ = suite.Point().Pick(nil, rand)
	}

	// Make two actual public/private keypairs (X[mine],x)
	mine1 := 1 // only the signer knows this
	mine2 := 2
	x1 := suite.Scalar().Pick(rand) // create a private key x
	x2 := suite.Scalar().Pick(rand)
	X[mine1] = suite.Point().Mul(nil, x1) // corresponding public key X
	X[mine2] = suite.Point().Mul(nil, x2)

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
	// 00000000  c6 e9 27 a5 00 5d 22 40  d2 a2 5d 08 44 2b ec 2e  |..'..]"@..].D+..|
	// 00000010  e2 01 a6 85 70 70 b4 73  2c 18 24 f1 46 44 22 09  |....pp.s,.$.FD".|
	// 00000020  1e 6d 18 7f 8b 95 e3 c4  b9 33 ad 94 69 b5 b4 13  |.m.......3..i...|
	// 00000030  b8 51 2f 24 a7 98 e4 06  f4 b2 f3 ee e8 73 de 78  |.Q/$.........s.x|
	// 00000040  a3 9d 4b 1c 74 6f 3a 50  89 c9 10 cc bb b0 5c a7  |..K.to:P......\.|
	// 00000050  09 a9 23 47 0f 36 08 a4  f3 46 ad 14 2d f0 9d c1  |..#G.6...F..-...|
	// 00000060  63 d3 5a 0e 97 78 e6 74  ce a0 24 34 c1 66 7d af  |c.Z..x.t..$4.f}.|
	// 00000070  32 9e 59 22 f2 9a 67 3c  ea e5 4f 54 6d 3e 07 f1  |2.Y"..g<..OTm>..|
	// 00000080  04 00 33 42 ee 88 9f 5d  fa 2e be 6a 72 fd 67 22  |..3B...]...jr.g"|
	// 00000090  c1 e0 ed 35 69 d7 e4 67  df 92 e7 ca 75 2f e6 72  |...5i..g....u/.r|
	// 000000a0  79 3a 32 e2 8b 45 61 e8  7d e5 95 5b 0a 30 35 e9  |y:2..Ea.}..[.05.|
	// 000000b0  af 3c 41 48 59 d9 e2 73  68 77 31 f3 36 cc ee 78  |.<AHY..shw1.6..x|
	// 000000c0  ab                                                |.|
	// Signature 1:
	// 00000000  69 4c 29 32 cb 9c f6 ca  80 72 f6 25 e0 ef 44 0b  |iL)2.....r.%..D.|
	// 00000010  f2 0b e3 ab 98 c4 62 a3  10 13 09 02 9a f1 f1 00  |......b.........|
	// 00000020  7f 03 ca 4f 75 84 fe 06  2c 9c 64 0e 99 c6 f1 91  |...Ou...,.d.....|
	// 00000030  62 43 48 b6 f8 20 41 2b  fa 59 e7 35 be f8 4c 1b  |bCH.. A+.Y.5..L.|
	// 00000040  f0 d8 af 83 ad 9a 87 55  ca be 46 f9 42 a2 dd 18  |.......U..F.B...|
	// 00000050  18 83 f1 f5 6d 82 e5 38  49 bf 24 9e 80 a4 12 eb  |....m..8I.$.....|
	// 00000060  56 c5 3f 08 bb 99 6d 7d  0a f8 ac c5 29 e8 94 54  |V.?...m}....)..T|
	// 00000070  3e 4d fb ca b5 1d 9a 29  56 a0 09 f9 ec 6d b5 28  |>M.....)V....m.(|
	// 00000080  04 00 33 42 ee 88 9f 5d  fa 2e be 6a 72 fd 67 22  |..3B...]...jr.g"|
	// 00000090  c1 e0 ed 35 69 d7 e4 67  df 92 e7 ca 75 2f e6 72  |...5i..g....u/.r|
	// 000000a0  79 3a 32 e2 8b 45 61 e8  7d e5 95 5b 0a 30 35 e9  |y:2..Ea.}..[.05.|
	// 000000b0  af 3c 41 48 59 d9 e2 73  68 77 31 f3 36 cc ee 78  |.<AHY..shw1.6..x|
	// 000000c0  ab                                                |.|
	// Signature 2:
	// 00000000  94 d0 51 98 05 a1 79 6c  16 4e 7f f2 58 c8 09 b8  |..Q...yl.N..X...|
	// 00000010  32 12 a5 dc be f3 cf 08  a8 77 8f 7e a7 32 dd 2b  |2........w.~.2.+|
	// 00000020  8b 48 7e 5a 4f eb 1d 1f  c8 6c 96 e6 38 86 a9 50  |.H~ZO....l..8..P|
	// 00000030  dc 69 e8 2d c9 ed 41 51  38 9d 5c 5f 9b e6 93 aa  |.i.-..AQ8.\_....|
	// 00000040  1c f7 7d 2f d1 ad 5c cd  4d ab 3a ed 2f 29 08 81  |..}/..\.M.:./)..|
	// 00000050  55 61 40 8d 86 88 cd e6  62 be 28 b4 90 9c ae 69  |Ua@.....b.(....i|
	// 00000060  54 1a 20 09 f3 84 ad 29  dc a8 64 cf c6 ec 92 f0  |T. ....)..d.....|
	// 00000070  76 0f 36 28 66 88 81 2b  59 43 0c 69 6f f2 7a 8e  |v.6(f..+YC.io.z.|
	// 00000080  04 80 18 09 20 80 e9 9b  39 bc 17 47 55 13 8f c9  |.... ...9..GU...|
	// 00000090  b4 9d 11 78 7b 56 0f f6  db 38 5f b4 f1 4f 3f 93  |...x{V...8_..O?.|
	// 000000a0  63 9c 33 ea 86 f6 e1 54  79 c9 14 9f 45 b6 88 59  |c.3....Ty...E..Y|
	// 000000b0  49 b6 76 99 c7 0c 84 6d  1a 9e 05 b0 30 c1 48 f2  |I.v....m....0.H.|
	// 000000c0  9a                                                |.|
	// Signature 3:
	// 00000000  1a 64 49 4a ff 66 bc 88  93 54 30 e9 96 89 34 76  |.dIJ.f...T0...4v|
	// 00000010  f6 95 e0 a9 84 8a a2 6e  f4 5e 7f db 58 d9 8a 48  |.......n.^..X..H|
	// 00000020  84 bd 96 a9 6b 6e c2 47  03 9f 18 33 73 a5 2b ee  |....kn.G...3s.+.|
	// 00000030  11 e1 99 36 bf 44 42 26  5e f8 cc 25 1e 8a 97 2b  |...6.DB&^..%...+|
	// 00000040  7f 57 93 33 c5 fb 27 9f  24 e9 d4 3f 1c 16 67 4c  |.W.3..'.$..?..gL|
	// 00000050  50 0b d1 0b 08 9b 0f 3f  cb ac 96 e8 92 3c a5 3d  |P......?.....<.=|
	// 00000060  d4 83 2c dd c6 6d e4 68  67 b7 dc 39 68 77 de 3d  |..,..m.hg..9hw.=|
	// 00000070  8c 83 0d b2 24 4b d6 17  e4 ce 78 7a 63 b7 f0 bb  |....$K....xzc...|
	// 00000080  04 80 18 09 20 80 e9 9b  39 bc 17 47 55 13 8f c9  |.... ...9..GU...|
	// 00000090  b4 9d 11 78 7b 56 0f f6  db 38 5f b4 f1 4f 3f 93  |...x{V...8_..O?.|
	// 000000a0  63 9c 33 ea 86 f6 e1 54  79 c9 14 9f 45 b6 88 59  |c.3....Ty...E..Y|
	// 000000b0  49 b6 76 99 c7 0c 84 6d  1a 9e 05 b0 30 c1 48 f2  |I.v....m....0.H.|
	// 000000c0  9a                                                |.|
	// Sig0 tag: 04003342ee889f5dfa2ebe6a72fd6722c1e0ed3569d7e467df92e7ca752fe672793a32e28b4561e87de5955b0a3035e9af3c414859d9e273687731f336ccee78ab
	// Sig1 tag: 04003342ee889f5dfa2ebe6a72fd6722c1e0ed3569d7e467df92e7ca752fe672793a32e28b4561e87de5955b0a3035e9af3c414859d9e273687731f336ccee78ab
	// Sig2 tag: 048018092080e99b39bc174755138fc9b49d11787b560ff6db385fb4f14f3f93639c33ea86f6e15479c9149f45b6885949b67699c70c846d1a9e05b030c148f29a
	// Sig3 tag: 048018092080e99b39bc174755138fc9b49d11787b560ff6db385fb4f14f3f93639c33ea86f6e15479c9149f45b6885949b67699c70c846d1a9e05b030c148f29a
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

func benchGenKeys(suite crypto.Suite,
	nkeys int) ([]crypto.Point, crypto.Scalar) {

	rand := random.Stream

	// Create an anonymity set of random "public keys"
	X := make([]crypto.Point, nkeys)
	for i := range X { // pick random points
		X[i], _ = suite.Point().Pick(nil, rand)
	}

	// Make just one of them an actual public/private keypair (X[mine],x)
	x := suite.Scalar().Pick(rand)
	X[0] = suite.Point().Mul(nil, x)

	return X, x
}

func benchGenKeysOpenSSL(nkeys int) ([]crypto.Point, crypto.Scalar) {
	return benchGenKeys(nist.NewAES128SHA256P256(), nkeys)
}
func benchGenSigOpenSSL(nkeys int) []byte {
	suite := nist.NewAES128SHA256P256()
	rand := suite.Cipher([]byte("example"))
	return Sign(suite, rand, benchMessage,
		Set(benchPubOpenSSL[:nkeys]), nil,
		0, benchPriOpenSSL)
}

func benchGenKeysEd25519(nkeys int) ([]crypto.Point, crypto.Scalar) {
	return benchGenKeys(edwards25519.NewAES128SHA256Ed25519(false), nkeys)
}
func benchGenSigEd25519(nkeys int) []byte {
	suite := edwards25519.NewAES128SHA256Ed25519(false)
	rand := suite.Cipher([]byte("example"))
	return Sign(suite, rand, benchMessage,
		Set(benchPubEd25519[:nkeys]), nil,
		0, benchPriEd25519)
}

func benchSign(suite crypto.Suite, pub []crypto.Point, pri crypto.Scalar,
	niter int) {
	rand := suite.Cipher([]byte("example"))
	for i := 0; i < niter; i++ {
		Sign(suite, rand, benchMessage, Set(pub), nil, 0, pri)
	}
}

func benchVerify(suite crypto.Suite, pub []crypto.Point,
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
	benchSign(edwards25519.NewAES128SHA256Ed25519(false),
		benchPubEd25519[:1], benchPriEd25519, b.N)
}
func BenchmarkSign10Ed25519(b *testing.B) {
	benchSign(edwards25519.NewAES128SHA256Ed25519(false),
		benchPubEd25519[:10], benchPriEd25519, b.N)
}
func BenchmarkSign100Ed25519(b *testing.B) {
	benchSign(edwards25519.NewAES128SHA256Ed25519(false),
		benchPubEd25519[:100], benchPriEd25519, b.N)
}

func BenchmarkVerify1Ed25519(b *testing.B) {
	benchVerify(edwards25519.NewAES128SHA256Ed25519(false),
		benchPubEd25519[:1], benchSig1Ed25519, b.N)
}
func BenchmarkVerify10Ed25519(b *testing.B) {
	benchVerify(edwards25519.NewAES128SHA256Ed25519(false),
		benchPubEd25519[:10], benchSig10Ed25519, b.N)
}
func BenchmarkVerify100Ed25519(b *testing.B) {
	benchVerify(edwards25519.NewAES128SHA256Ed25519(false),
		benchPubEd25519[:100], benchSig100Ed25519, b.N)
}
