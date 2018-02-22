package anon

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/dedis/kyber"
	"github.com/dedis/kyber/group/edwards25519"
	"github.com/dedis/kyber/util/random"
	"github.com/dedis/kyber/xof/blake2xb"
)

// This example demonstrates signing and signature verification
// using a trivial "anonymity set" of size 1, i.e., no anonymity.
// In this special case the signing scheme devolves to
// producing traditional ElGamal signatures:
// the resulting signatures are exactly the same length
// and represent essentially the same computational cost.
func ExampleSign_one() {
	// Crypto setup: Get a suite which returns a predictable
	// random number stream for this example.
	// In production, simply use edwards25519.NewBlakeSHA256Ed25519()
	suite := edwards25519.NewBlakeSHA256Ed25519WithRand(blake2xb.New(nil))

	// Create a public/private keypair (X[mine],x)
	X := make([]kyber.Point, 1)
	mine := 0                                      // which public key is mine
	x := suite.Scalar().Pick(suite.RandomStream()) // create a private key x
	X[mine] = suite.Point().Mul(x, nil)            // corresponding public key X

	// Generate the signature
	M := []byte("Hello World!") // message we want to sign
	sig := Sign(suite, M, Set(X), nil, mine, x)
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
	// 00000000  45 30 41 6a 51 d1 01 cf  7e ee 63 66 1d e9 e3 cf  |E0AjQ...~.cf....|
	// 00000010  a3 d2 1b 98 fc 46 99 6d  9f 91 cc 65 f4 9d 10 03  |.....F.m...e....|
	// 00000020  45 a0 e0 5a bc fe 62 62  45 a9 e5 eb 00 e2 6b 66  |E..Z..bbE.....kf|
	// 00000030  dc aa f0 53 7c 10 3e bf  bd f6 30 8d 2d 2c 5c 0f  |...S|.>...0.-,\.|
	// Signature verified against correct message.
	// Verifying against wrong message: invalid signature
}

// This example demonstrates how to create unlinkable anonymity-set signatures,
// and to verify them,
// using a small anonymity set containing three public keys.
func ExampleSign_anonSet() {
	// Crypto setup: Get a suite which returns a predictable
	// random number stream for this example.
	// In production, simply use edwards25519.NewBlakeSHA256Ed25519()
	suite := edwards25519.NewBlakeSHA256Ed25519WithRand(blake2xb.New(nil))

	// Create an anonymity set of random "public keys"
	X := make([]kyber.Point, 3)
	for i := range X { // pick random points
		X[i] = suite.Point().Pick(suite.RandomStream())
	}

	// Make just one of them an actual public/private keypair (X[mine],x)
	mine := 1                                      // only the signer knows this
	x := suite.Scalar().Pick(suite.RandomStream()) // create a private key x
	X[mine] = suite.Point().Mul(x, nil)            // corresponding public key X

	// Generate the signature
	M := []byte("Hello World!") // message we want to sign
	sig := Sign(suite, M, Set(X), nil, mine, x)
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
	// 00000000  dc 43 94 ce 5e c5 ab c1  f8 3e bd e1 30 a8 19 bd  |.C..^....>..0...|
	// 00000010  13 f7 b4 0d f0 f5 39 40  c3 de 71 26 f9 1c ba 0f  |......9@..q&....|
	// 00000020  61 f7 23 a0 e6 7c 95 b7  e4 b2 32 55 40 d4 25 87  |a.#..|....2U@.%.|
	// 00000030  da d4 76 18 01 22 fb c7  93 f7 40 6b d6 e0 e7 0b  |..v.."....@k....|
	// 00000040  3d a3 1f 32 50 f8 c1 d2  c6 93 f4 19 e0 c7 2a 06  |=..2P.........*.|
	// 00000050  ef 6f 1c 4d c9 4f 0e db  c8 30 4d 20 94 52 e8 04  |.o.M.O...0M .R..|
	// 00000060  f4 6d eb 7c 5f 30 09 60  bf c7 37 cd 44 16 fe bb  |.m.|_0.`..7.D...|
	// 00000070  b6 5a e5 45 b3 6c 7f b1  12 6d 60 b9 9f 60 0e 0c  |.Z.E.l...m`..`..|
	// Signature verified against correct message.
	// Verifying against wrong message: invalid signature
}

// This example demonstrates the creation of linkable anonymity set signatures,
// and verification, using an anonymity set containing three public keys.
// We produce four signatures, two from each of two private key-holders,
// demonstrating how the resulting verifiable tags distinguish
// signatures by the same key-holder from signatures by different key-holders.
func ExampleSign_linkable() {
	// Crypto setup: Get a suite which returns a predictable
	// random number stream for this example.
	// In production, simply use edwards25519.NewBlakeSHA256Ed25519()
	suite := edwards25519.NewBlakeSHA256Ed25519WithRand(blake2xb.New(nil))
	rand := suite.RandomStream()

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
	sig[0] = Sign(suite, M, Set(X), S, mine1, x1)
	sig[1] = Sign(suite, M, Set(X), S, mine1, x1)
	sig[2] = Sign(suite, M, Set(X), S, mine2, x2)
	sig[3] = Sign(suite, M, Set(X), S, mine2, x2)
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
	// 00000000  a2 f1 f3 e3 07 35 6c a9  16 fb 4f c9 a7 35 c7 3b  |.....5l...O..5.;|
	// 00000010  7f 09 8b 70 45 8d 5f c1  2b 74 22 f2 bf 3d d1 0a  |...pE._.+t"..=..|
	// 00000020  4b 8b 88 78 28 d6 5f 77  d0 d6 1b 26 47 cb 7a 2e  |K..x(._w...&G.z.|
	// 00000030  3c f8 8c 4b 8b 39 cd 3e  92 e1 2c 2d ac 7f db 01  |<..K.9.>..,-....|
	// 00000040  1b 1d c2 e4 1d fd 54 b9  29 b9 f1 ec 9c e1 bc c8  |......T.).......|
	// 00000050  b5 db c8 9f 71 1c 48 1c  2c 02 b2 14 de e7 b6 08  |....q.H.,.......|
	// 00000060  61 f7 23 a0 e6 7c 95 b7  e4 b2 32 55 40 d4 25 87  |a.#..|....2U@.%.|
	// 00000070  da d4 76 18 01 22 fb c7  93 f7 40 6b d6 e0 e7 0b  |..v.."....@k....|
	// 00000080  da 86 5d 31 13 21 f5 95  70 d8 d7 a1 26 3b 47 dd  |..]1.!..p...&;G.|
	// 00000090  60 5d c2 1d 38 bf b7 49  e9 47 4a 8d 89 a4 b0 89  |`]..8..I.GJ.....|
	// Signature 1:
	// 00000000  14 b6 dd a5 99 0c e7 f7  d5 82 43 d5 45 84 19 7b  |..........C.E..{|
	// 00000010  db c6 3b f5 ee ce 01 50  17 57 58 21 37 31 25 0d  |..;....P.WX!71%.|
	// 00000020  81 b1 81 c3 f3 00 f9 0f  9d 58 58 5f 66 f4 52 75  |.........XX_f.Ru|
	// 00000030  0f bb bc fc 25 58 f7 29  74 8a 57 79 93 75 d9 0b  |....%X.)t.Wy.u..|
	// 00000040  11 3d 25 cb be 39 0f 88  2c f8 ee 63 93 d8 98 94  |.=%..9..,..c....|
	// 00000050  1b 85 fd 38 0a 37 87 0b  c1 db a7 53 50 72 98 0c  |...8.7.....SPr..|
	// 00000060  7f 9a fb 37 f7 64 66 5c  7c b5 1f 2d b1 d5 63 67  |...7.df\|..-..cg|
	// 00000070  12 1b d4 18 0a 5b 42 b2  c0 9e 3a 42 e2 c2 77 0c  |.....[B...:B..w.|
	// 00000080  da 86 5d 31 13 21 f5 95  70 d8 d7 a1 26 3b 47 dd  |..]1.!..p...&;G.|
	// 00000090  60 5d c2 1d 38 bf b7 49  e9 47 4a 8d 89 a4 b0 89  |`]..8..I.GJ.....|
	// Signature 2:
	// 00000000  5f 11 1a 2f 10 28 55 d9  e2 be 10 56 7e 57 37 ae  |_../.(U....V~W7.|
	// 00000010  7a a1 bc ec 87 0f 98 4f  52 cc 70 e6 14 79 8a 01  |z......OR.p..y..|
	// 00000020  89 f7 f8 b6 91 d1 52 f7  f0 b2 3d 3c 70 f1 95 9e  |......R...=<p...|
	// 00000030  2b 3b 76 1c d6 9e 2f 77  09 83 6a 7f 4d d8 4d 09  |+;v.../w..j.M.M.|
	// 00000040  98 6f d5 7f 3b c0 00 e9  f7 80 0d ed 3c 15 b7 58  |.o..;.......<..X|
	// 00000050  ba c2 c2 53 84 ff d0 6f  47 c3 b6 e6 24 66 19 00  |...S...oG...$f..|
	// 00000060  9f a5 96 bf 08 a4 3f 2b  bd 26 f2 0b 79 b9 92 c2  |......?+.&..y...|
	// 00000070  00 6b f8 71 2a 95 60 07  92 4a 3b 86 c4 1b 98 0a  |.k.q*.`..J;.....|
	// 00000080  49 d9 9a 38 a8 da c4 44  3d 6b 56 70 78 9e f0 01  |I..8...D=kVpx...|
	// 00000090  c6 da 3e d2 ff 20 b0 7c  0e 88 c6 52 a1 60 f5 6a  |..>.. .|...R.`.j|
	// Signature 3:
	// 00000000  a9 0f 3b 86 6f 4e c6 ea  8d e8 57 2c 1a 20 c6 14  |..;.oN....W,. ..|
	// 00000010  5e 5b 66 95 0b 41 ce 57  94 a1 f0 36 73 cd c8 04  |^[f..A.W...6s...|
	// 00000020  ff 47 7b f3 6e ee 9e 1f  bb 0d 96 e7 b8 50 1d 9f  |.G{.n........P..|
	// 00000030  8f bf ea bc ef f3 d5 d9  9b 05 9b d3 5e c9 41 0e  |............^.A.|
	// 00000040  d1 e8 a3 f6 7b b4 8e 38  db 73 4a ef ca 9a 68 7b  |....{..8.sJ...h{|
	// 00000050  c3 d0 2a e3 a9 e5 c1 a3  b7 bb 60 92 75 f1 7e 00  |..*.......`.u.~.|
	// 00000060  9a bd 63 f7 c0 cf 2d a1  4d 1e 2c 40 ff 11 d6 4f  |..c...-.M.,@...O|
	// 00000070  c5 a2 70 ab 14 2e 11 ee  24 e6 ca ca 15 e2 f7 0f  |..p.....$.......|
	// 00000080  49 d9 9a 38 a8 da c4 44  3d 6b 56 70 78 9e f0 01  |I..8...D=kVpx...|
	// 00000090  c6 da 3e d2 ff 20 b0 7c  0e 88 c6 52 a1 60 f5 6a  |..>.. .|...R.`.j|
	// Sig0 tag: da865d311321f59570d8d7a1263b47dd605dc21d38bfb749e9474a8d89a4b089
	// Sig1 tag: da865d311321f59570d8d7a1263b47dd605dc21d38bfb749e9474a8d89a4b089
	// Sig2 tag: 49d99a38a8dac4443d6b5670789ef001c6da3ed2ff20b07c0e88c652a160f56a
	// Sig3 tag: 49d99a38a8dac4443d6b5670789ef001c6da3ed2ff20b07c0e88c652a160f56a
}

var benchMessage = []byte("Hello World!")

var benchPubEd25519, benchPriEd25519 = benchGenKeysEd25519(100)
var benchSig1Ed25519 = benchGenSigEd25519(1)
var benchSig10Ed25519 = benchGenSigEd25519(10)
var benchSig100Ed25519 = benchGenSigEd25519(100)

func benchGenKeys(g kyber.Group,
	nkeys int) ([]kyber.Point, kyber.Scalar) {
	rng := random.New()

	// Create an anonymity set of random "public keys"
	X := make([]kyber.Point, nkeys)
	for i := range X { // pick random points
		X[i] = g.Point().Pick(rng)
	}

	// Make just one of them an actual public/private keypair (X[mine],x)
	x := g.Scalar().Pick(rng)
	X[0] = g.Point().Mul(x, nil)

	return X, x
}

func benchGenKeysEd25519(nkeys int) ([]kyber.Point, kyber.Scalar) {
	return benchGenKeys(edwards25519.NewBlakeSHA256Ed25519(), nkeys)
}
func benchGenSigEd25519(nkeys int) []byte {
	suite := edwards25519.NewBlakeSHA256Ed25519()
	return Sign(suite, benchMessage,
		Set(benchPubEd25519[:nkeys]), nil,
		0, benchPriEd25519)
}

func benchSign(suite Suite, pub []kyber.Point, pri kyber.Scalar,
	niter int) {
	for i := 0; i < niter; i++ {
		Sign(suite, benchMessage, Set(pub), nil, 0, pri)
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
	benchSign(edwards25519.NewBlakeSHA256Ed25519(),
		benchPubEd25519[:1], benchPriEd25519, b.N)
}
func BenchmarkSign10Ed25519(b *testing.B) {
	benchSign(edwards25519.NewBlakeSHA256Ed25519(),
		benchPubEd25519[:10], benchPriEd25519, b.N)
}
func BenchmarkSign100Ed25519(b *testing.B) {
	benchSign(edwards25519.NewBlakeSHA256Ed25519(),
		benchPubEd25519[:100], benchPriEd25519, b.N)
}

func BenchmarkVerify1Ed25519(b *testing.B) {
	benchVerify(edwards25519.NewBlakeSHA256Ed25519(),
		benchPubEd25519[:1], benchSig1Ed25519, b.N)
}
func BenchmarkVerify10Ed25519(b *testing.B) {
	benchVerify(edwards25519.NewBlakeSHA256Ed25519(),
		benchPubEd25519[:10], benchSig10Ed25519, b.N)
}
func BenchmarkVerify100Ed25519(b *testing.B) {
	benchVerify(edwards25519.NewBlakeSHA256Ed25519(),
		benchPubEd25519[:100], benchSig100Ed25519, b.N)
}
