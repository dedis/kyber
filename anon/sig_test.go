package anon

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"github.com/dedis/crypto/abstract"
	"github.com/dedis/crypto/edwards"
	"github.com/dedis/crypto/openssl"
	"github.com/dedis/crypto/random"
	"testing"
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
	rand := suite.Cipher([]byte("example"))

	// Create a public/private keypair (X[mine],x)
	X := make([]abstract.Point, 1)
	mine := 0                           // which public key is mine
	x := suite.Secret().Pick(rand)      // create a private key x
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
	// 00000000  ca e3 63 fd 0f a9 25 bd  f0 c6 f4 e4 93 3a 3d c0  |..c...%......:=.|
	// 00000010  be 2d ee d1 7f 78 b5 d4  30 00 05 fa 2d ab f3 08  |.-...x..0...-...|
	// 00000020  ac 50 83 66 b9 9f 55 f4  79 48 28 66 cc 25 fb 16  |.P.f..U.yH(f.%..|
	// 00000030  60 d5 0f 88 d6 8d af 97  24 5d 00 ec de 2c 9b ed  |`.......$]...,..|
	// Signature verified against correct message.
	// Verifying against wrong message: invalid signature
}

// This example demonstrates how to create unlinkable anonymity-set signatures,
// and to verify them,
// using a small anonymity set containing three public keys.
func ExampleSign_anonSet() {

	// Crypto setup
	suite := openssl.NewAES128SHA256P256()
	rand := suite.Cipher([]byte("example"))

	// Create an anonymity set of random "public keys"
	X := make([]abstract.Point, 3)
	for i := range X { // pick random points
		X[i], _ = suite.Point().Pick(nil, rand)
	}

	// Make just one of them an actual public/private keypair (X[mine],x)
	mine := 1                           // only the signer knows this
	x := suite.Secret().Pick(rand)      // create a private key x
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
	// 00000000  05 e5 e3 f4 80 22 d8 38  03 63 e6 9d b5 2c 51 28  |.....".8.c...,Q(|
	// 00000010  7c f1 78 cd 7d f2 0e dd  a0 63 58 04 d7 79 ce 03  ||.x.}....cX..y..|
	// 00000020  56 b2 b5 3a e1 c8 8c f7  29 8a 13 75 59 98 ea ce  |V..:....)..uY...|
	// 00000030  f4 6d d5 d0 62 85 51 8e  fe d9 4a 02 1f 35 03 33  |.m..b.Q...J..5.3|
	// 00000040  bf 19 a6 0e b2 47 8d 8e  91 b1 a7 70 5c 62 6d d9  |.....G.....p\bm.|
	// 00000050  70 2a 39 f0 a0 60 59 c2  4e 76 2b d1 0e 06 29 2d  |p*9..`Y.Nv+...)-|
	// 00000060  71 eb 40 46 de 61 2f 08  8d 9a 04 09 d7 a1 62 83  |q.@F.a/.......b.|
	// 00000070  48 e3 cc 09 af 64 26 df  df da d6 51 62 5d e6 2b  |H....d&....Qb].+|
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
	rand := suite.Cipher([]byte("example"))

	// Create an anonymity set of random "public keys"
	X := make([]abstract.Point, 3)
	for i := range X { // pick random points
		X[i], _ = suite.Point().Pick(nil, rand)
	}

	// Make two actual public/private keypairs (X[mine],x)
	mine1 := 1 // only the signer knows this
	mine2 := 2
	x1 := suite.Secret().Pick(rand) // create a private key x
	x2 := suite.Secret().Pick(rand)
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
	// 00000000  7f 0d 4b b1 47 ca 5e f5  4c 2f b3 71 44 1a 08 04  |..K.G.^.L/.qD...|
	// 00000010  02 d2 67 43 3b 58 19 69  56 44 73 b3 49 bd 19 ce  |..gC;X.iVDs.I...|
	// 00000020  d3 63 d3 5a 0e 97 78 e6  74 ce a0 24 34 c1 66 7d  |.c.Z..x.t..$4.f}|
	// 00000030  af 32 9e 59 22 f2 9a 67  3c ea e5 4f 54 6d 3e 07  |.2.Y"..g<..OTm>.|
	// 00000040  dc db 8a df 92 93 55 e0  19 8d 7c f5 58 a1 5a aa  |......U...|.X.Z.|
	// 00000050  80 97 d9 48 84 2b f0 0d  ab 39 2e d4 40 67 08 f4  |...H.+...9..@g..|
	// 00000060  56 b2 b5 3a e1 c8 8c f7  29 8a 13 75 59 98 ea ce  |V..:....)..uY...|
	// 00000070  f4 6d d5 d0 62 85 51 8e  fe d9 4a 02 1f 35 03 33  |.m..b.Q...J..5.3|
	// 00000080  03 37 8f df 75 d4 0b 9d  6c ba f1 c9 07 77 37 59  |.7..u...l....w7Y|
	// 00000090  1e cd 2a 18 75 93 18 c0  6d ee d8 d0 fc ad d5 00  |..*.u...m.......|
	// 000000a0  ab                                                |.|
	// Signature 1:
	// 00000000  c0 c4 72 60 8e 83 8c 15  bf 56 d2 6f 1e 1a 9b 63  |..r`.....V.o...c|
	// 00000010  07 5f f4 6d fb 5b d4 fc  35 e2 46 52 53 41 3a 67  |._.m.[..5.FRSA:g|
	// 00000020  27 56 c5 3f 08 bb 99 6d  7d 0a f8 ac c5 29 e8 94  |'V.?...m}....)..|
	// 00000030  54 3e 4d fb ca b5 1d 9a  29 56 a0 09 f9 ec 6d b5  |T>M.....)V....m.|
	// 00000040  ac c5 1e 6a 65 72 46 a7  9c 11 d0 8c d0 d8 89 ad  |...jerF.........|
	// 00000050  61 0c 2a 89 1a 4d af 86  49 8f 14 87 dd 64 0e 2f  |a.*..M..I....d./|
	// 00000060  78 fd f8 95 ec ee a5 50  a8 65 b0 63 35 f2 83 05  |x......P.e.c5...|
	// 00000070  21 9d cf f1 0d a1 85 6a  3f ca 8d 68 31 1f e0 e2  |!......j?..h1...|
	// 00000080  03 37 8f df 75 d4 0b 9d  6c ba f1 c9 07 77 37 59  |.7..u...l....w7Y|
	// 00000090  1e cd 2a 18 75 93 18 c0  6d ee d8 d0 fc ad d5 00  |..*.u...m.......|
	// 000000a0  ab                                                |.|
	// Signature 2:
	// 00000000  a4 8e 61 72 a4 72 18 81  55 df 8c e0 3a 01 92 05  |..ar.r..U...:...|
	// 00000010  f2 73 29 5a 6f 27 fd 55  d9 b4 a3 62 f2 e0 7f d3  |.s)Zo'.U...b....|
	// 00000020  1b 1e 8f 0b b0 e6 16 78  31 46 7f b6 32 90 f7 5e  |.......x1F..2..^|
	// 00000030  ad fb ea 42 2b a6 46 ba  fd c0 26 f3 21 af 31 9c  |...B+.F...&.!.1.|
	// 00000040  a4 8b 48 7e 5a 4f eb 1d  1f c8 6c 96 e6 38 86 a9  |..H~ZO....l..8..|
	// 00000050  50 dc 69 e8 2d c9 ed 41  51 38 9d 5c 5f 9b e6 93  |P.i.-..AQ8.\_...|
	// 00000060  ef 3e 03 10 5e b1 0b 03  19 2c bb db 46 ef ad 1b  |.>..^....,..F...|
	// 00000070  d6 25 92 98 92 aa 96 b5  d8 38 f8 5c b9 68 7a c2  |.%.......8.\.hz.|
	// 00000080  02 55 a2 af 44 5e 5b fb  65 b1 d5 6f ea 18 21 4a  |.U..D^[.e..o..!J|
	// 00000090  4b 0a 75 3b 6e 50 b7 ed  9f e7 49 aa 03 83 d1 76  |K.u;nP....I....v|
	// 000000a0  7f                                                |.|
	// Signature 3:
	// 00000000  43 cb 80 12 94 b9 f7 da  e1 93 84 66 75 22 8b 8e  |C..........fu"..|
	// 00000010  61 ff ed 65 f1 4e e4 3e  ed 4d 98 3e 5c 6c 7a 2c  |a..e.N.>.M.>\lz,|
	// 00000020  69 56 c6 9e 1b eb dd cd  02 42 d4 50 cf 66 7f 4f  |iV.......B.P.f.O|
	// 00000030  c4 33 92 36 a0 b7 94 a5  3e fb 9b 19 bd 7c ea ce  |.3.6....>....|..|
	// 00000040  69 84 bd 96 a9 6b 6e c2  47 03 9f 18 33 73 a5 2b  |i....kn.G...3s.+|
	// 00000050  ee 11 e1 99 36 bf 44 42  26 5e f8 cc 25 1e 8a 97  |....6.DB&^..%...|
	// 00000060  30 06 bf af 76 ed 06 2d  f6 ed 72 33 53 e4 8a e0  |0...v..-..r3S...|
	// 00000070  a8 88 84 48 69 dd 4b d9  ff e3 d7 4a cf 04 88 c9  |...Hi.K....J....|
	// 00000080  02 55 a2 af 44 5e 5b fb  65 b1 d5 6f ea 18 21 4a  |.U..D^[.e..o..!J|
	// 00000090  4b 0a 75 3b 6e 50 b7 ed  9f e7 49 aa 03 83 d1 76  |K.u;nP....I....v|
	// 000000a0  7f                                                |.|
	// Sig0 tag: 03378fdf75d40b9d6cbaf1c9077737591ecd2a18759318c06deed8d0fcadd500ab
	// Sig1 tag: 03378fdf75d40b9d6cbaf1c9077737591ecd2a18759318c06deed8d0fcadd500ab
	// Sig2 tag: 0255a2af445e5bfb65b1d56fea18214a4b0a753b6e50b7ed9fe749aa0383d1767f
	// Sig3 tag: 0255a2af445e5bfb65b1d56fea18214a4b0a753b6e50b7ed9fe749aa0383d1767f
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

func benchGenKeys(suite abstract.Suite,
	nkeys int) ([]abstract.Point, abstract.Secret) {

	rand := random.Stream

	// Create an anonymity set of random "public keys"
	X := make([]abstract.Point, nkeys)
	for i := range X { // pick random points
		X[i], _ = suite.Point().Pick(nil, rand)
	}

	// Make just one of them an actual public/private keypair (X[mine],x)
	x := suite.Secret().Pick(rand)
	X[0] = suite.Point().Mul(nil, x)

	return X, x
}

func benchGenKeysOpenSSL(nkeys int) ([]abstract.Point, abstract.Secret) {
	return benchGenKeys(openssl.NewAES128SHA256P256(), nkeys)
}
func benchGenSigOpenSSL(nkeys int) []byte {
	suite := openssl.NewAES128SHA256P256()
	rand := suite.Cipher([]byte("example"))
	return Sign(suite, rand, benchMessage,
		Set(benchPubOpenSSL[:nkeys]), nil,
		0, benchPriOpenSSL)
}

func benchGenKeysEd25519(nkeys int) ([]abstract.Point, abstract.Secret) {
	return benchGenKeys(edwards.NewAES128SHA256Ed25519(false), nkeys)
}
func benchGenSigEd25519(nkeys int) []byte {
	suite := edwards.NewAES128SHA256Ed25519(false)
	rand := suite.Cipher([]byte("example"))
	return Sign(suite, rand, benchMessage,
		Set(benchPubEd25519[:nkeys]), nil,
		0, benchPriEd25519)
}

func benchSign(suite abstract.Suite, pub []abstract.Point, pri abstract.Secret,
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
	benchSign(openssl.NewAES128SHA256P256(),
		benchPubOpenSSL[:1], benchPriOpenSSL, b.N)
}
func BenchmarkSign10OpenSSL(b *testing.B) {
	benchSign(openssl.NewAES128SHA256P256(),
		benchPubOpenSSL[:10], benchPriOpenSSL, b.N)
}
func BenchmarkSign100OpenSSL(b *testing.B) {
	benchSign(openssl.NewAES128SHA256P256(),
		benchPubOpenSSL[:100], benchPriOpenSSL, b.N)
}

func BenchmarkVerify1OpenSSL(b *testing.B) {
	benchVerify(openssl.NewAES128SHA256P256(),
		benchPubOpenSSL[:1], benchSig1OpenSSL, b.N)
}
func BenchmarkVerify10OpenSSL(b *testing.B) {
	benchVerify(openssl.NewAES128SHA256P256(),
		benchPubOpenSSL[:10], benchSig10OpenSSL, b.N)
}
func BenchmarkVerify100OpenSSL(b *testing.B) {
	benchVerify(openssl.NewAES128SHA256P256(),
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
