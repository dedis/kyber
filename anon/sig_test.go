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
	// 00000000  28 6e 4f 15 12 4a 4c ee  9d a8 44 5f fa b2 a4 5b  |(nO..JL...D_...[|
	// 00000010  79 73 d9 86 34 e3 d6 95  f9 0b 55 f9 24 69 5b 97  |ys..4.....U.$i[.|
	// 00000020  35 4f 8e 91 3c 11 27 9b  5f 3c 61 19 44 96 76 ff  |5O..<.'._<a.D.v.|
	// 00000030  91 88 74 90 98 56 1a 57  27 75 8b 31 a7 40 76 92  |..t..V.W'u.1.@v.|
	// 00000040  f9 49 5b 4b 0e 54 6d 14  6f 77 77 ff b7 90 33 76  |.I[K.Tm.oww...3v|
	// 00000050  fb 8f bb 66 f4 94 8f 28  dc 85 b9 24 df b7 86 72  |...f...(...$...r|
	// 00000060  71 eb 40 46 de 3b a1 91  f9 24 93 30 f8 2b eb b6  |q.@F.;...$.0.+..|
	// 00000070  a0 ef 31 22 46 b7 64 f5  cf 79 d7 7b 7b 96 91 09  |..1"F.d..y.{{...|
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
	// 00000000  ba bd 11 0f fd 5d 28 0b  31 2c ff 06 0e 2b 9a 8f  |.....](.1,...+..|
	// 00000010  0e 51 76 59 bf 5e ba 24  49 b6 ab 66 f3 c5 e8 cf  |.QvY.^.$I..f....|
	// 00000020  08 27 b2 b7 99 f0 80 6d  66 2d e2 5f 0d c8 cd b1  |.'.....mf-._....|
	// 00000030  3e 46 90 eb d4 42 c4 1c  96 9b 93 aa 4e 7e 29 4f  |>F...B......N~)O|
	// 00000040  ab 06 5f 0f b0 12 89 49  6d d8 12 6b 2b 4f c2 3d  |.._....Im..k+O.=|
	// 00000050  a2 24 8a c5 d6 72 5c bd  1e 80 ea ac 3e ca 03 58  |.$...r\.....>..X|
	// 00000060  35 4f 8e 91 3c 11 27 9b  5f 3c 61 19 44 96 76 ff  |5O..<.'._<a.D.v.|
	// 00000070  91 88 74 90 98 56 1a 57  27 75 8b 31 a7 40 76 92  |..t..V.W'u.1.@v.|
	// 00000080  03 37 8f df 75 d4 0b 9d  6c ba f1 c9 07 77 37 59  |.7..u...l....w7Y|
	// 00000090  1e cd 2a 18 75 93 18 c0  6d ee d8 d0 fc ad d5 00  |..*.u...m.......|
	// 000000a0  ab                                                |.|
	// Signature 1:
	// 00000000  bf bf 44 65 9b 91 13 d4  26 33 97 85 ab 2c 25 84  |..De....&3...,%.|
	// 00000010  1e a5 54 57 35 69 87 ea  7a 33 82 34 f0 f5 69 b9  |..TW5i..z3.4..i.|
	// 00000020  70 a4 f9 d2 29 d1 c1 25  64 7c 34 d1 8a 75 80 95  |p...)..%d|4..u..|
	// 00000030  46 2e d6 8d cb 86 b0 6c  07 31 05 72 a6 d1 1e 5b  |F......l.1.r...[|
	// 00000040  d0 01 bf 11 77 72 da 32  0c 79 2d 4a 74 5c bd ef  |....wr.2.y-Jt\..|
	// 00000050  fd a4 de b9 db 66 9e b2  53 a2 78 36 1b 63 31 89  |.....f..S.x6.c1.|
	// 00000060  f5 0c 43 c2 9a eb d5 f4  d2 34 2c d9 c2 a2 98 ab  |..C......4,.....|
	// 00000070  bb 32 a9 75 83 6b 9f 31  12 73 d4 1d 54 a4 34 e2  |.2.u.k.1.s..T.4.|
	// 00000080  03 37 8f df 75 d4 0b 9d  6c ba f1 c9 07 77 37 59  |.7..u...l....w7Y|
	// 00000090  1e cd 2a 18 75 93 18 c0  6d ee d8 d0 fc ad d5 00  |..*.u...m.......|
	// 000000a0  ab                                                |.|
	// Signature 2:
	// 00000000  29 88 50 99 33 65 8f d1  99 d1 86 4c c1 5b 1c 55  |).P.3e.....L.[.U|
	// 00000010  fe a2 9c 82 1a 98 17 f6  0c 7b 47 51 56 5d fc b8  |.........{GQV]..|
	// 00000020  39 f8 e4 94 c9 5e 05 d9  52 97 50 fc 69 5b ad 00  |9....^..R.P.i[..|
	// 00000030  a1 83 01 a0 64 ee b8 54  c1 75 7d 93 e8 ce 50 84  |....d..T.u}...P.|
	// 00000040  35 1e 12 45 be 02 88 d7  08 b3 4f fa 9e 09 9e b6  |5..E......O.....|
	// 00000050  3e 8c 2c c6 77 f0 62 8b  76 8d 39 02 4f db 08 5b  |>.,.w.b.v.9.O..[|
	// 00000060  c8 01 bf 47 e3 89 5c 81  e4 f5 ff 4c cf b8 fe 3b  |...G..\....L...;|
	// 00000070  84 83 73 26 7a a1 be 21  17 f2 39 e9 5c 70 7f 06  |..s&z..!..9.\p..|
	// 00000080  02 55 a2 af 44 5e 5b fb  65 b1 d5 6f ea 18 21 4a  |.U..D^[.e..o..!J|
	// 00000090  4b 0a 75 3b 6e 50 b7 ed  9f e7 49 aa 03 83 d1 76  |K.u;nP....I....v|
	// 000000a0  7f                                                |.|
	// Signature 3:
	// 00000000  f5 4e b1 1c bd 05 0e 19  34 21 0b a8 7a 0b 78 f3  |.N......4!..z.x.|
	// 00000010  17 e9 89 4f fa 10 2c 25  0d 47 1a a3 17 d6 a6 a4  |...O..,%.G......|
	// 00000020  91 50 de 29 d9 92 65 db  7e 0b 6b 3d 0b d4 c5 8f  |.P.)..e.~.k=....|
	// 00000030  e9 d6 b5 db ee 85 03 c5  f2 3e 94 ea c0 a9 1a ab  |.........>......|
	// 00000040  b0 4b fd 7d 90 ec d2 15  6f dc 7c fb 61 61 3b 73  |.K.}....o.|.aa;s|
	// 00000050  b3 f8 1f 07 78 7f 21 b5  e1 4a 17 15 d4 64 44 42  |....x.!..J...dDB|
	// 00000060  5d a8 9b 0b a4 b0 c9 b7  9f 8b 71 99 70 17 0d 30  |].........q.p..0|
	// 00000070  9c 5e ff dd 24 77 76 4d  09 5b 64 1f 41 15 71 4d  |.^..$wvM.[d.A.qM|
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
