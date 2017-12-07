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
	suite := edwards25519.NewBlakeSHA256Ed25519()
	rand := suite.XOF([]byte("example"))

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
	// 00000000  cf 77 57 89 0c c6 18 24  25 20 a3 94 7a 48 63 8b  |.wW....$% ..zHc.|
	// 00000010  a0 e4 9a 61 52 89 97 21  07 05 12 4e 4e fd f1 03  |...aR..!...NN...|
	// 00000020  04 b9 a2 74 55 96 7c 15  eb 9b c8 d6 ec 00 46 f7  |...tU.|.......F.|
	// 00000030  41 6d c2 8d 0a da 3f 20  d6 46 2c 6e ff a6 8e 01  |Am....? .F,n....|
	// Signature verified against correct message.
	// Verifying against wrong message: invalid signature
}

// This example demonstrates how to create unlinkable anonymity-set signatures,
// and to verify them,
// using a small anonymity set containing three public keys.
func ExampleSign_anonSet() {

	// Crypto setup
	suite := edwards25519.NewBlakeSHA256Ed25519()
	rand := suite.XOF([]byte("example"))

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
	// 00000000  85 d3 c8 8f df 1c 0f c5  85 a9 06 b3 a8 7a 86 ca  |.............z..|
	// 00000010  93 f1 89 20 08 52 77 0b  fb ba ae 0d dc 1c b3 09  |... .Rw.........|
	// 00000020  d1 cc 1e e1 f4 3b 88 52  e5 99 ed 50 d7 66 b5 76  |.....;.R...P.f.v|
	// 00000030  59 6c c1 66 98 07 e5 73  e7 b8 fe 48 43 a0 74 09  |Yl.f...s...HC.t.|
	// 00000040  3c 8e 50 67 3b db 59 3d  43 cf df 86 b0 7e 0d 33  |<.Pg;.Y=C....~.3|
	// 00000050  65 a7 18 df 3e 22 2f 48  7f c5 c0 70 27 d6 c0 0c  |e...>"/H...p'...|
	// 00000060  8d 0e c0 14 e3 eb 8b e9  16 40 29 60 ab bd e6 1a  |.........@)`....|
	// 00000070  68 54 5e 29 c8 85 05 bc  4a 27 83 d9 32 cc 74 0f  |hT^)....J'..2.t.|
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
	suite := edwards25519.NewBlakeSHA256Ed25519()
	rand := suite.XOF([]byte("example"))

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
	// 00000000  92 08 4b 1a d8 0a 53 74  8a 16 6e ef ae 89 62 3c  |..K...St..n...b<|
	// 00000010  60 e5 65 84 92 05 a8 58  5d 1a 73 bc 3e 70 73 03  |`.e....X].s.>ps.|
	// 00000020  84 9a 7b ec 21 aa ff c7  fc 79 c6 8f f4 23 82 e7  |..{.!....y...#..|
	// 00000030  d3 71 69 20 d6 94 27 ef  11 0b 4c a5 79 54 1f 09  |.qi ..'...L.yT..|
	// 00000040  cc b0 ee af f9 51 01 57  63 15 ae 7c 37 ca 21 4d  |.....Q.Wc..|7.!M|
	// 00000050  81 fa 64 32 e2 fe fb 7b  8e fb 89 96 de 44 cf 0c  |..d2...{.....D..|
	// 00000060  d1 cc 1e e1 f4 3b 88 52  e5 99 ed 50 d7 66 b5 76  |.....;.R...P.f.v|
	// 00000070  59 6c c1 66 98 07 e5 73  e7 b8 fe 48 43 a0 74 09  |Yl.f...s...HC.t.|
	// 00000080  79 42 cf f0 50 2a 53 56  18 9c 9d 7e 71 4c af dc  |yB..P*SV...~qL..|
	// 00000090  51 b0 d7 e3 78 c5 06 c0  88 b6 6c 96 41 e1 d2 2a  |Q...x.....l.A..*|
	// Signature 1:
	// 00000000  0d 37 de 03 b1 76 63 26  1e 45 47 d1 da 0d ec 83  |.7...vc&.EG.....|
	// 00000010  c0 44 c1 c9 99 de 2d 01  4b 71 5b 70 a9 87 1a 06  |.D....-.Kq[p....|
	// 00000020  b9 fe 59 0b f8 72 15 1d  7b d8 f7 78 1a 63 e5 a6  |..Y..r..{..x.c..|
	// 00000030  25 bb d5 25 95 66 3f d1  ea 4b 6d b8 bf 78 dc 0d  |%..%.f?..Km..x..|
	// 00000040  16 d7 1d 8a c2 a3 b5 10  d4 06 11 e1 3c 6a e6 b2  |............<j..|
	// 00000050  5b 41 7c 41 53 09 6a 81  34 fe 73 96 25 99 54 0d  |[A|AS.j.4.s.%.T.|
	// 00000060  b0 68 27 8d a4 df db 05  95 21 cc 81 c9 94 5b 1e  |.h'......!....[.|
	// 00000070  98 84 58 b0 e2 7b 51 f6  59 a5 45 4e b8 26 80 09  |..X..{Q.Y.EN.&..|
	// 00000080  79 42 cf f0 50 2a 53 56  18 9c 9d 7e 71 4c af dc  |yB..P*SV...~qL..|
	// 00000090  51 b0 d7 e3 78 c5 06 c0  88 b6 6c 96 41 e1 d2 2a  |Q...x.....l.A..*|
	// Signature 2:
	// 00000000  e6 31 e4 b3 61 6e b7 72  68 09 c2 fe f5 09 44 7b  |.1..an.rh.....D{|
	// 00000010  56 8e 96 3b ad 1e a4 e5  85 82 e2 13 5a 47 fb 01  |V..;........ZG..|
	// 00000020  96 ce ba b3 dd 48 ab 35  b8 ee c1 b0 c3 0e 50 ba  |.....H.5......P.|
	// 00000030  e2 f7 ea c0 4e ce e4 54  6e 5f 07 3b af 79 15 01  |....N..Tn_.;.y..|
	// 00000040  73 eb a2 ab c3 b9 83 33  9c 4f 82 96 3d 39 db 77  |s......3.O..=9.w|
	// 00000050  25 ff 2e 50 a6 b6 d5 e6  9e a5 fa ea 9b 8a 2b 0f  |%..P..........+.|
	// 00000060  05 a3 fd 02 a4 69 98 99  68 03 87 2e 91 a6 87 2b  |.....i..h......+|
	// 00000070  68 0f a9 21 95 0b 46 3b  76 a7 e2 50 40 8a 1d 01  |h..!..F;v..P@...|
	// 00000080  d7 d6 a6 84 b4 2b 30 05  10 53 ae 40 8e 66 39 97  |.....+0..S.@.f9.|
	// 00000090  e2 a6 b2 b7 0b 00 d9 2b  35 6e 45 aa 0c 11 61 de  |.......+5nE...a.|
	// Signature 3:
	// 00000000  91 15 6e ce 3f 73 40 b7  71 c7 86 ad 18 a3 52 0e  |..n.?s@.q.....R.|
	// 00000010  e1 f4 09 cd 3c f7 f4 0d  8d d0 f5 34 86 a4 f4 09  |....<......4....|
	// 00000020  1d 07 01 b3 f7 31 26 52  84 ce 22 47 a9 37 53 c8  |.....1&R.."G.7S.|
	// 00000030  0e bc a4 41 ce 74 3f f4  08 57 ca 3e 21 93 44 04  |...A.t?..W.>!.D.|
	// 00000040  51 f6 64 82 c3 d1 61 e6  c4 6e af 7b 2b 70 55 be  |Q.d...a..n.{+pU.|
	// 00000050  72 75 d1 20 e4 1f 88 15  20 b9 5c c6 df 19 8a 0a  |ru. .... .\.....|
	// 00000060  f9 e2 7a 3b 19 fb 6f 5c  76 8d d4 60 06 0a 17 57  |..z;..o\v..`...W|
	// 00000070  70 aa b3 b3 a6 70 9e 53  30 cc db b8 6a b3 1a 0e  |p....p.S0...j...|
	// 00000080  d7 d6 a6 84 b4 2b 30 05  10 53 ae 40 8e 66 39 97  |.....+0..S.@.f9.|
	// 00000090  e2 a6 b2 b7 0b 00 d9 2b  35 6e 45 aa 0c 11 61 de  |.......+5nE...a.|
	// Sig0 tag: 7942cff0502a5356189c9d7e714cafdc51b0d7e378c506c088b66c9641e1d22a
	// Sig1 tag: 7942cff0502a5356189c9d7e714cafdc51b0d7e378c506c088b66c9641e1d22a
	// Sig2 tag: d7d6a684b42b30051053ae408e663997e2a6b2b70b00d92b356e45aa0c1161de
	// Sig3 tag: d7d6a684b42b30051053ae408e663997e2a6b2b70b00d92b356e45aa0c1161de
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
	rand := suite.XOF([]byte("example"))
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
