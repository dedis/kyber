package anon

import (
	"bytes"
	"encoding/hex"
	"fmt"

	"github.com/dedis/kyber"
	"github.com/dedis/kyber/group/edwards25519"
	"github.com/dedis/kyber/xof"
)

// This example shows how to encrypt with a trivial signer set
// of one public key.
func ExampleEncrypt() {
	// Crypto setup
	suite := edwards25519.NewAES128SHA256Ed25519()
	rand := xof.New().Absorb([]byte("fixed seed for example purposes"))

	// Create a public/private keypair (X[mine],x)
	X := make([]kyber.Point, 1)
	mine := 0                           // which public key is mine
	x := suite.Scalar().Pick(rand)      // create a private key x
	X[mine] = suite.Point().Mul(x, nil) // corresponding public key X

	// Encrypt a message with the public key
	M := []byte("Hello World!") // message to encrypt
	C := Encrypt(suite, rand, M, Set(X), false)
	fmt.Printf("Encryption of '%s':\n%s", string(M), hex.Dump(C))

	// Decrypt the ciphertext with the private key
	MM, err := Decrypt(suite, C, Set(X), mine, x, false)
	if err != nil {
		fmt.Println(err.Error())
		return
	}
	if !bytes.Equal(M, MM) {
		fmt.Println("Decryption failed to reproduce message")
		return
	}
	fmt.Printf("Decrypted: '%s'\n", string(MM))

	// Output:
	// Encryption of 'Hello World!':
	// 00000000  b3 ac 56 ec 87 02 d7 2d  01 8a f8 51 15 02 fa cf  |..V....-...Q....|
	// 00000010  b0 8c 7f ba e9 c5 39 71  3c ca 11 20 87 94 71 63  |......9q<.. ..qc|
	// 00000020  3d cc bc bf 00 4d 97 7a  99 38 ad a0 22 c2 15 65  |=....M.z.8.."..e|
	// 00000030  1f bb db 5b 83 02 fa 8f  ea 5a 95 e2 ea 36 33 f9  |...[.....Z...63.|
	// 00000040  52 e8 2d c1 cc d2 22 fe  d2 c5 99 3d 64 3b f4 de  |R.-..."....=d;..|
	// 00000050  4b b1 a0 b1 b2 75 d3 a6  e5 34 d0 fe ab 9b f1 45  |K....u...4.....E|
	// 00000060  9e 4b 90 45 fc 47 fb dd  dc 15 d8 4c f9 5e af c3  |.K.E.G.....L.^..|
	// 00000070  af 4a b7 a4 3e 29 e6 e9  66 4d 6a 78 bb 01 7a 7e  |.J..>)..fMjx..z~|
	// 00000080  47 bf 5d 3c 62 36 5e 24  7f 53 f7 d8 3a 33 5a cf  |G.]<b6^$.S..:3Z.|
	// 00000090  fe ab 98 af                                       |....|
	// Decrypted: 'Hello World!'
}

// This example shows how to encrypt with a set of 3 keys, 2 of which are
// random and one (X[mine], mine == 1) is the real public key.
func ExampleEncrypt_anonSet() {
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

	// Encrypt a message with all the public keys
	M := []byte("Hello World!") // message to encrypt
	C := Encrypt(suite, rand, M, Set(X), false)
	fmt.Printf("Encryption of '%s':\n%s", string(M), hex.Dump(C))

	// Decrypt the ciphertext with the known private key
	MM, err := Decrypt(suite, C, Set(X), mine, x, false)
	if err != nil {
		fmt.Println(err.Error())
		return
	}
	if !bytes.Equal(M, MM) {
		fmt.Println("Decryption failed to reproduce message")
		return
	}
	fmt.Printf("Decrypted: '%s'\n", string(MM))

	// Output:
	// Encryption of 'Hello World!':
	// 00000000  cd 02 e6 d4 31 0d c2 43  e5 bc 29 da 55 29 04 ee  |....1..C..).U)..|
	// 00000010  b6 bb 71 6c 9c b5 8b e9  c2 be 1b 91 15 6f d2 60  |..ql.........o.`|
	// 00000020  e5 3b 74 7b 15 31 eb 23  9d a1 8a 3c b4 69 28 8c  |.;t{.1.#...<.i(.|
	// 00000030  65 73 1b 79 07 80 4c 41  34 90 ad 62 f1 67 84 63  |es.y..LA4..b.g.c|
	// 00000040  de d2 0a a4 21 5e f0 c6  88 78 d9 4f c4 8f fc ce  |....!^...x.O....|
	// 00000050  7f ed d7 a8 39 c1 d2 28  3d a8 80 d8 6f 0e 94 2a  |....9..(=...o..*|
	// 00000060  cf 72 4b 14 0a 7c 33 4f  46 ab 0c 0e 2b df 74 12  |.rK..|3OF...+.t.|
	// 00000070  78 00 8d 04 4b 0f 00 b2  02 b7 a9 5f e8 b0 78 06  |x...K......_..x.|
	// 00000080  c6 e8 f2 2f 8d 77 2a ea  a7 db 35 84 64 db d0 bc  |.../.w*...5.d...|
	// 00000090  82 a8 eb 13 5f d6 ea 25  79 96 fd d0 46 b6 3d 60  |...._..%y...F.=`|
	// 000000a0  e6 46 33 c5 70 18 30 7d  65 d4 49 0d 2e a9 f8 e9  |.F3.p.0}e.I.....|
	// 000000b0  f4 4f 43 6f 11 11 b3 af  f9 d8 14 8f 74 9e 68 c3  |.OCo........t.h.|
	// 000000c0  0d 96 ef f5 40 3c 7e ff  d9 bd 3f 01 52 60 a3 9e  |....@<~...?.R`..|
	// 000000d0  2a dc 96 1e                                       |*...|
	// Decrypted: 'Hello World!'
}
