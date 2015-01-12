package anon

import (
	"fmt"
	"bytes"
	"testing"
	"encoding/hex"
	"github.com/dedis/crypto/abstract"
	"github.com/dedis/crypto/random"
	"github.com/dedis/crypto/openssl"
	"github.com/dedis/crypto/edwards"
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
	rand := abstract.HashStream(suite, []byte("example"), nil)

	// Create a public/private keypair (X[mine],x)
	X := make([]abstract.Point,1)
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
	// 00000000  bc 27 0a 81 0b f2 cc dc  4f cc a8 1c 9b 30 d3 a5  |.'......O....0..|
	// 00000010  42 a5 c1 f5 b7 57 6d e9  55 4d 7d f7 14 1e ac 3e  |B....Wm.UM}....>|
	// 00000020  87 05 b1 45 f1 a8 cc c1  bb 22 79 20 4e 69 5a 67  |...E....."y NiZg|
	// 00000030  a2 0a b1 fd cd 89 bd 72  d8 c7 01 b0 94 2b 91 04  |.......r.....+..|
	// Signature verified against correct message.
	// Verifying against wrong message: invalid signature
}

// This example demonstrates how to create unlinkable anonymity-set signatures,
// and to verify them,
// using a small anonymity set containing three public keys.
func ExampleSign_anonSet() {

	// Crypto setup
	suite := openssl.NewAES128SHA256P256()
	rand := abstract.HashStream(suite, []byte("example"), nil)

	// Create an anonymity set of random "public keys"
	X := make([]abstract.Point,3)
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
	// 00000000  3c 01 3e f3 fc 5b 71 b4  64 3d 67 db da a8 72 38  |<.>..[q.d=g...r8|
	// 00000010  68 76 dd ef f5 0b e3 64  91 92 2c b3 e7 e2 0b d0  |hv.....d..,.....|
	// 00000020  cd 81 38 63 31 f1 fd 65  ac 28 1a e5 1b 7c d2 14  |..8c1..e.(...|..|
	// 00000030  a0 58 05 2d c1 61 aa 85  c7 88 5b cf 04 b5 96 9c  |.X.-.a....[.....|
	// 00000040  c7 b6 fc 24 9e cc 1d e6  23 fa ae 16 bb 85 fe 12  |...$....#.......|
	// 00000050  ee 1a 3a ad 21 24 c4 23  a0 04 2b 5c f1 fb c0 1e  |..:.!$.#..+\....|
	// 00000060  d1 3b 09 b8 54 9f b1 0b  4d fc 6b 2c 3f 32 d6 20  |.;..T...M.k,?2. |
	// 00000070  16 ed 89 a3 be 09 97 33  74 02 94 c6 7d f1 55 71  |.......3t...}.Uq|
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
	rand := abstract.HashStream(suite, []byte("example"), nil)

	// Create an anonymity set of random "public keys"
	X := make([]abstract.Point,3)
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
	// 00000000  a0 08 de 0e 16 06 ef 76  4d d6 d8 cb a5 df 31 75  |.......vM.....1u|
	// 00000010  46 63 3f 72 63 f7 0c 4c  0f bc be 3a 56 92 b1 0c  |Fc?rc..L...:V...|
	// 00000020  66 48 3c bf ec 24 7c 25  e7 de 5f 93 53 09 6b cc  |fH<..$|%.._.S.k.|
	// 00000030  2b 06 2f 7b 43 95 d4 0b  c1 c4 f8 06 33 e2 8a 56  |+./{C.......3..V|
	// 00000040  ea c6 f2 19 d7 1d b6 b0  7c c2 bc 54 43 c2 af 13  |........|..TC...|
	// 00000050  19 d7 67 9d f4 a7 89 49  30 cc b5 63 47 58 c3 9e  |..g....I0..cGX..|
	// 00000060  cd 81 38 63 31 f1 fd 65  ac 28 1a e5 1b 7c d2 14  |..8c1..e.(...|..|
	// 00000070  a0 58 05 2d c1 61 aa 85  c7 88 5b cf 04 b5 96 9c  |.X.-.a....[.....|
	// 00000080  03 f5 ea d7 1e b3 9d cb  24 a6 7a b0 e0 fd e7 4a  |........$.z....J|
	// 00000090  c1 76 86 84 ca 48 e1 02  ad 0d 81 1d 73 19 5f 6d  |.v...H......s._m|
	// 000000a0  e9                                                |.|
	// Signature 1:
	// 00000000  1c a5 02 18 11 2a db 2f  fb e8 1d 83 87 72 c7 55  |.....*./.....r.U|
	// 00000010  03 a0 3c 59 9a 4c 60 91  61 ac c3 7b f1 26 e2 31  |..<Y.L`.a..{.&.1|
	// 00000020  0e 4a 04 80 86 96 8b b5  ce f3 64 05 90 46 ff 60  |.J........d..F.`|
	// 00000030  9a 2c d9 6c 64 90 c1 31  0e a1 28 92 7b a4 dc c2  |.,.ld..1..(.{...|
	// 00000040  4e af fa a3 3e 36 18 13  ad fd e0 3a 46 dd aa 36  |N...>6.....:F..6|
	// 00000050  4d ea eb d3 66 a9 75 88  af 21 79 91 db 7d 20 b4  |M...f.u..!y..} .|
	// 00000060  86 2e c1 ce ff dd db c1  14 d3 de 43 b1 23 e0 dc  |...........C.#..|
	// 00000070  5f c9 66 ef 19 a2 ba 89  51 17 72 1f 2c 83 5e 90  |_.f.....Q.r.,.^.|
	// 00000080  03 f5 ea d7 1e b3 9d cb  24 a6 7a b0 e0 fd e7 4a  |........$.z....J|
	// 00000090  c1 76 86 84 ca 48 e1 02  ad 0d 81 1d 73 19 5f 6d  |.v...H......s._m|
	// 000000a0  e9                                                |.|
	// Signature 2:
	// 00000000  36 c6 d0 08 bf cd 90 4a  f1 90 a1 d7 0c 21 23 bc  |6......J.....!#.|
	// 00000010  c7 5c bc 7f 40 04 d4 8c  5d 34 12 9b 61 21 86 aa  |.\..@...]4..a!..|
	// 00000020  21 3a 04 da 1a 7d 21 87  e0 6b 5f ec e1 81 08 83  |!:...}!..k_.....|
	// 00000030  9d 7c 81 5f e6 55 da 4a  46 05 29 44 5e 64 f8 53  |.|._.U.JF.)D^d.S|
	// 00000040  06 f6 76 65 43 fc 84 68  04 48 e6 14 9c 94 50 e4  |..veC..h.H....P.|
	// 00000050  a4 56 17 bc de 99 e3 38  20 f0 ac 44 ff e5 a9 5c  |.V.....8 ..D...\|
	// 00000060  4c 52 26 57 7d 69 9b 66  2f 2a b8 cf ac b0 ac b1  |LR&W}i.f/*......|
	// 00000070  8f 3c da be 6c f3 24 39  6a f7 f7 7b d6 96 04 bb  |.<..l.$9j..{....|
	// 00000080  03 4d 8d 9d 65 e4 01 80  c3 37 12 70 59 a5 84 42  |.M..e....7.pY..B|
	// 00000090  8d 72 74 1c f7 16 05 f6  eb bb ae 83 dc fd 62 95  |.rt...........b.|
	// 000000a0  14                                                |.|
	// Signature 3:
	// 00000000  59 c4 52 22 4a ea 3b 43  27 4d b3 1a 80 4d ac af  |Y.R"J.;C'M...M..|
	// 00000010  36 35 0c c7 b3 6e d7 02  85 0d 06 bd a3 1e a1 7c  |65...n.........||
	// 00000020  f9 1e 6c f0 4e 81 92 1e  33 84 d9 60 0c bc dd cd  |..l.N...3..`....|
	// 00000030  be c7 71 52 2e 7f 32 ff  c2 5c 58 d0 9c 6c 59 2d  |..qR..2..\X..lY-|
	// 00000040  25 3a ba 34 c5 a2 f8 46  cb d2 f9 8a 3e a8 a6 0d  |%:.4...F....>...|
	// 00000050  b2 4e ed 8f 33 82 94 69  56 5b c7 40 74 78 de 23  |.N..3..iV[.@tx.#|
	// 00000060  11 fc fd f2 5f 3e ab 7f  ec ef d8 8d 18 30 9c 36  |...._>.......0.6|
	// 00000070  68 77 39 b2 cf 38 b0 18  eb 34 f2 a0 f4 e1 29 2b  |hw9..8...4....)+|
	// 00000080  03 4d 8d 9d 65 e4 01 80  c3 37 12 70 59 a5 84 42  |.M..e....7.pY..B|
	// 00000090  8d 72 74 1c f7 16 05 f6  eb bb ae 83 dc fd 62 95  |.rt...........b.|
	// 000000a0  14                                                |.|
	// Sig0 tag: 03f5ead71eb39dcb24a67ab0e0fde74ac1768684ca48e102ad0d811d73195f6de9
	// Sig1 tag: 03f5ead71eb39dcb24a67ab0e0fde74ac1768684ca48e102ad0d811d73195f6de9
	// Sig2 tag: 034d8d9d65e40180c337127059a584428d72741cf71605f6ebbbae83dcfd629514
	// Sig3 tag: 034d8d9d65e40180c337127059a584428d72741cf71605f6ebbbae83dcfd629514
}


var benchMessage = []byte("Hello World!")

var benchPubOpenSSL,benchPriOpenSSL = benchGenKeysOpenSSL(100)
var benchSig1OpenSSL = benchGenSigOpenSSL(1)
var benchSig10OpenSSL = benchGenSigOpenSSL(10)
var benchSig100OpenSSL = benchGenSigOpenSSL(100)

var benchPubEd25519,benchPriEd25519 = benchGenKeysEd25519(100)
var benchSig1Ed25519 = benchGenSigEd25519(1)
var benchSig10Ed25519 = benchGenSigEd25519(10)
var benchSig100Ed25519 = benchGenSigEd25519(100)

func benchGenKeys(suite abstract.Suite,
		nkeys int) ([]abstract.Point,abstract.Secret) {

	rand := random.Stream

	// Create an anonymity set of random "public keys"
	X := make([]abstract.Point,nkeys)
	for i := range(X) {			// pick random points
		X[i],_ = suite.Point().Pick(nil,rand)
	}

	// Make just one of them an actual public/private keypair (X[mine],x)
	x := suite.Secret().Pick(rand)
	X[0] = suite.Point().Mul(nil,x)

	return X,x
}

func benchGenKeysOpenSSL(nkeys int) ([]abstract.Point,abstract.Secret) {
	return benchGenKeys(openssl.NewAES128SHA256P256(), nkeys)
}
func benchGenSigOpenSSL(nkeys int) []byte {
	suite := openssl.NewAES128SHA256P256()
	rand := abstract.HashStream(suite, []byte("example"), nil)
	return Sign(suite, rand, benchMessage,
			Set(benchPubOpenSSL[:nkeys]), nil,
			0, benchPriOpenSSL)
}

func benchGenKeysEd25519(nkeys int) ([]abstract.Point,abstract.Secret) {
	return benchGenKeys(edwards.NewAES128SHA256Ed25519(false), nkeys)
}
func benchGenSigEd25519(nkeys int) []byte {
	suite := edwards.NewAES128SHA256Ed25519(false)
	rand := abstract.HashStream(suite, []byte("example"), nil)
	return Sign(suite, rand, benchMessage,
			Set(benchPubEd25519[:nkeys]), nil,
			0, benchPriEd25519)
}

func benchSign(suite abstract.Suite, pub []abstract.Point, pri abstract.Secret,
		niter int) {
	rand := abstract.HashStream(suite, []byte("example"), nil)
	for i := 0; i < niter; i++ {
		Sign(suite, rand, benchMessage, Set(pub), nil, 0, pri)
	}
}

func benchVerify(suite abstract.Suite, pub []abstract.Point,
		sig []byte, niter int) {
	for i := 0; i < niter; i++ {
		tag,err := Verify(suite, benchMessage, Set(pub), nil, sig)
		if tag == nil || err != nil {
			panic("benchVerify failed")
		}
	}
}

func BenchmarkSign1OpenSSL(b *testing.B) {
	benchSign(openssl.NewAES128SHA256P256(),
		benchPubOpenSSL[:1],benchPriOpenSSL,b.N)
}
func BenchmarkSign10OpenSSL(b *testing.B) {
	benchSign(openssl.NewAES128SHA256P256(),
		benchPubOpenSSL[:10],benchPriOpenSSL,b.N)
}
func BenchmarkSign100OpenSSL(b *testing.B) {
	benchSign(openssl.NewAES128SHA256P256(),
		benchPubOpenSSL[:100],benchPriOpenSSL,b.N)
}

func BenchmarkVerify1OpenSSL(b *testing.B) {
	benchVerify(openssl.NewAES128SHA256P256(),
		benchPubOpenSSL[:1],benchSig1OpenSSL,b.N)
}
func BenchmarkVerify10OpenSSL(b *testing.B) {
	benchVerify(openssl.NewAES128SHA256P256(),
		benchPubOpenSSL[:10],benchSig10OpenSSL,b.N)
}
func BenchmarkVerify100OpenSSL(b *testing.B) {
	benchVerify(openssl.NewAES128SHA256P256(),
		benchPubOpenSSL[:100],benchSig100OpenSSL,b.N)
}

func BenchmarkSign1Ed25519(b *testing.B) {
	benchSign(edwards.NewAES128SHA256Ed25519(false),
		benchPubEd25519[:1],benchPriEd25519,b.N)
}
func BenchmarkSign10Ed25519(b *testing.B) {
	benchSign(edwards.NewAES128SHA256Ed25519(false),
		benchPubEd25519[:10],benchPriEd25519,b.N)
}
func BenchmarkSign100Ed25519(b *testing.B) {
	benchSign(edwards.NewAES128SHA256Ed25519(false),
		benchPubEd25519[:100],benchPriEd25519,b.N)
}

func BenchmarkVerify1Ed25519(b *testing.B) {
	benchVerify(edwards.NewAES128SHA256Ed25519(false),
		benchPubEd25519[:1],benchSig1Ed25519,b.N)
}
func BenchmarkVerify10Ed25519(b *testing.B) {
	benchVerify(edwards.NewAES128SHA256Ed25519(false),
		benchPubEd25519[:10],benchSig10Ed25519,b.N)
}
func BenchmarkVerify100Ed25519(b *testing.B) {
	benchVerify(edwards.NewAES128SHA256Ed25519(false),
		benchPubEd25519[:100],benchSig100Ed25519,b.N)
}

