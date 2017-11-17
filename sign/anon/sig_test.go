package anon

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/dedis/kyber"
	"github.com/dedis/kyber/group/edwards25519"
	"github.com/dedis/kyber/xof"
)

// This example demonstrates signing and signature verification
// using a trivial "anonymity set" of size 1, i.e., no anonymity.
// In this special case the signing scheme devolves to
// producing traditional ElGamal signatures:
// the resulting signatures are exactly the same length
// and represent essentially the same computational cost.
func ExampleSign() {

	// Crypto setup
	suite := edwards25519.NewAES128SHA256Ed25519()
	rand := xof.New().Absorb([]byte("fixed seed for example purposes"))

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
	// 00000000  5f 70 ec 1a 2e c0 e9 c1  b8 d3 e2 cf 90 bf 0b b8  |_p..............|
	// 00000010  89 8f 84 74 3e e3 27 4a  20 51 c5 65 2e b6 74 0c  |...t>.'J Q.e..t.|
	// 00000020  8b fa 0a f7 c9 33 bf e8  ba 18 15 11 e4 51 73 56  |.....3.......QsV|
	// 00000030  ac 51 e4 c8 a4 35 2f a7  09 d0 85 fc e1 ba f1 0f  |.Q...5/.........|
	// Signature verified against correct message.
	// Verifying against wrong message: invalid signature
}

// This example demonstrates how to create unlinkable anonymity-set signatures,
// and to verify them,
// using a small anonymity set containing three public keys.
func ExampleSign_anonSet() {

	// Crypto setup
	suite := edwards25519.NewAES128SHA256Ed25519()
	rand := xof.New().Absorb([]byte("fixed seed for example purposes"))

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
	// 00000000  aa 7e 93 a8 66 41 34 34  7f 4b d7 15 79 dc f8 e2  |.~..fA44.K..y...|
	// 00000010  03 cd 17 9a 3a ed 98 0c  f3 3d 29 0c 45 f3 d3 0f  |....:....=).E...|
	// 00000020  47 49 09 13 de 12 14 7e  d8 f2 ee a6 a0 b3 63 6c  |GI.....~......cl|
	// 00000030  9e c5 b5 6d 73 39 1c 8e  c7 fa f7 dd 3b 4e 4e 04  |...ms9......;NN.|
	// 00000040  48 01 e5 7e 6e 5e a2 60  38 e8 19 f2 5d 56 f0 d6  |H..~n^.`8...]V..|
	// 00000050  1e b2 11 8b 0d fd e0 1d  9b e2 2d 78 66 a9 7f 0c  |..........-xf...|
	// 00000060  06 e4 5d 62 7b b3 91 51  83 c7 e0 8c 25 5b 81 d1  |..]b{..Q....%[..|
	// 00000070  b7 df ce 0e ef 82 15 32  53 de bd fa 0a 35 ef 01  |.......2S....5..|
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
	rand := xof.New().Absorb([]byte("fixed seed for example purposes"))

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
	// 00000000  20 44 af 58 98 d0 ec 07  fb 79 9d bb e3 69 62 32  | D.X.....y...ib2|
	// 00000010  b9 e6 92 cd 09 3a 5e ed  f0 01 3a f2 8c 12 8b 06  |.....:^...:.....|
	// 00000020  69 95 11 bf 68 d2 4a 90  99 a9 aa 39 fa da 04 fd  |i...h.J....9....|
	// 00000030  eb 86 ff 9e 20 85 5b c8  ae e0 f2 a3 3c a1 b5 03  |.... .[.....<...|
	// 00000040  e6 96 9b f5 bd 1f a4 1c  07 5c 07 8f 92 d1 e1 a0  |.........\......|
	// 00000050  12 fa 18 51 80 75 69 4b  64 a4 55 3c 3e 6f 12 0b  |...Q.uiKd.U<>o..|
	// 00000060  47 49 09 13 de 12 14 7e  d8 f2 ee a6 a0 b3 63 6c  |GI.....~......cl|
	// 00000070  9e c5 b5 6d 73 39 1c 8e  c7 fa f7 dd 3b 4e 4e 04  |...ms9......;NN.|
	// 00000080  5e f0 aa d6 1e c2 00 94  f5 22 9c 7b a5 cc d0 f8  |^........".{....|
	// 00000090  13 09 5c 14 88 d3 c8 77  c9 6c 3c b5 46 1a cf 66  |..\....w.l<.F..f|
	// Signature 1:
	// 00000000  ab 97 8a d8 cb 82 91 43  40 44 ae 98 ec 8b 70 c0  |.......C@D....p.|
	// 00000010  76 1c d8 16 8d 4d 55 7c  d8 c9 f9 f7 11 6c 10 08  |v....MU|.....l..|
	// 00000020  5d 38 9e 47 3e 36 78 bb  fc 3d 63 8f e9 d9 70 cf  |]8.G>6x..=c...p.|
	// 00000030  ab fb d7 77 be 09 b7 fa  5a fe 77 d6 cd d7 fe 0f  |...w....Z.w.....|
	// 00000040  6b 5d f4 8c a3 80 34 4c  b1 12 7c 0e d2 92 ba 74  |k]....4L..|....t|
	// 00000050  25 dd a3 f7 43 14 ce 9d  9a 4a d1 4f 0f f5 98 00  |%...C....J.O....|
	// 00000060  ff d1 2f 46 1d 3e 90 84  78 c2 11 22 f8 66 13 e9  |../F.>..x..".f..|
	// 00000070  d0 85 9f f4 49 a0 3e 11  27 22 e7 29 b1 6b f0 0d  |....I.>.'".).k..|
	// 00000080  5e f0 aa d6 1e c2 00 94  f5 22 9c 7b a5 cc d0 f8  |^........".{....|
	// 00000090  13 09 5c 14 88 d3 c8 77  c9 6c 3c b5 46 1a cf 66  |..\....w.l<.F..f|
	// Signature 2:
	// 00000000  7f 05 9f 6a c8 0d 83 ee  ea e8 36 7d 40 b0 5e 87  |...j......6}@.^.|
	// 00000010  9b 34 75 1f 2f 4b 68 b7  cc 83 9b 3e a8 fb 14 06  |.4u./Kh....>....|
	// 00000020  f3 10 c8 55 8c c0 65 0a  5f 1c cb 66 f8 aa 52 81  |...U..e._..f..R.|
	// 00000030  08 d4 a4 ec 8b 5e 24 24  bc 38 0d 0d 26 db 3d 08  |.....^$$.8..&.=.|
	// 00000040  92 b8 2c 25 c4 69 41 a9  27 fa 54 37 d5 cf 21 96  |..,%.iA.'.T7..!.|
	// 00000050  15 58 27 8c 76 d3 5d 8d  4b 55 9e ec b4 f8 e6 08  |.X'.v.].KU......|
	// 00000060  d4 a8 95 41 21 4c 1f 5b  65 ae 0e 56 dd 78 89 89  |...A!L.[e..V.x..|
	// 00000070  4e 22 e9 5d a4 0f 6d cf  a0 a8 83 4c 96 18 42 0a  |N".]..m....L..B.|
	// 00000080  50 de 08 19 7f c4 55 41  bf 6e eb 1f 60 c6 b4 65  |P.....UA.n..`..e|
	// 00000090  d2 84 80 82 c6 62 02 57  b9 8b 46 c3 97 37 49 0e  |.....b.W..F..7I.|
	// Signature 3:
	// 00000000  11 24 29 56 6b 9d 54 73  4a 35 db c1 60 34 2f 6d  |.$)Vk.TsJ5..`4/m|
	// 00000010  93 31 4a 07 29 b5 4c 3f  ac 6a af 36 d5 e0 b2 08  |.1J.).L?.j.6....|
	// 00000020  20 21 13 14 de 39 d1 68  e5 89 28 0e c4 30 21 63  | !...9.h..(..0!c|
	// 00000030  c4 db 1f f1 1f eb f2 3f  3b f5 b4 36 fd c7 b4 0e  |.......?;..6....|
	// 00000040  5b 6f a9 78 56 2e 02 6d  2d 35 03 1c 49 05 6e e3  |[o.xV..m-5..I.n.|
	// 00000050  8f 41 74 d9 3d 64 53 94  ce b0 fe fa 41 7e 30 0e  |.At.=dS.....A~0.|
	// 00000060  53 15 9e 14 f2 e7 8f 9f  c1 a1 83 0c 48 48 34 28  |S...........HH4(|
	// 00000070  b9 9d 49 3c fe 21 f9 34  bb 28 ac 3a 22 53 56 0d  |..I<.!.4.(.:"SV.|
	// 00000080  50 de 08 19 7f c4 55 41  bf 6e eb 1f 60 c6 b4 65  |P.....UA.n..`..e|
	// 00000090  d2 84 80 82 c6 62 02 57  b9 8b 46 c3 97 37 49 0e  |.....b.W..F..7I.|
	// Sig0 tag: 5ef0aad61ec20094f5229c7ba5ccd0f813095c1488d3c877c96c3cb5461acf66
	// Sig1 tag: 5ef0aad61ec20094f5229c7ba5ccd0f813095c1488d3c877c96c3cb5461acf66
	// Sig2 tag: 50de08197fc45541bf6eeb1f60c6b465d2848082c6620257b98b46c39737490e
	// Sig3 tag: 50de08197fc45541bf6eeb1f60c6b465d2848082c6620257b98b46c39737490e
}

var benchMessage = []byte("Hello World!")

var benchPubEd25519, benchPriEd25519 = benchGenKeysEd25519(100)
var benchSig1Ed25519 = benchGenSigEd25519(1)
var benchSig10Ed25519 = benchGenSigEd25519(10)
var benchSig100Ed25519 = benchGenSigEd25519(100)

func benchGenKeys(g kyber.Group,
	nkeys int) ([]kyber.Point, kyber.Scalar) {

	rng := xof.New()
	seed := make([]byte, rng.Rate())
	_, err := rand.Read(seed)
	if err != nil {
		panic(err)
	}
	rng.Absorb(seed)

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
	return benchGenKeys(edwards25519.NewAES128SHA256Ed25519(), nkeys)
}
func benchGenSigEd25519(nkeys int) []byte {
	suite := edwards25519.NewAES128SHA256Ed25519()
	rand := xof.New().Absorb([]byte("fixed seed for example purposes"))
	return Sign(suite, rand, benchMessage,
		Set(benchPubEd25519[:nkeys]), nil,
		0, benchPriEd25519)
}

func benchSign(suite Suite, pub []kyber.Point, pri kyber.Scalar,
	b *testing.B) {
	rand := xof.New().Absorb([]byte("fixed seed for example purposes"))
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
