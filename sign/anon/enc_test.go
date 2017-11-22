package anon

import (
	"bytes"
	"fmt"
	//"testing"
	"encoding/hex"

	"github.com/dedis/kyber"
	"github.com/dedis/kyber/group/edwards25519"
)

func Example_encrypt1() {

	// Crypto setup
	suite := edwards25519.NewAES128SHA256Ed25519()
	rand := suite.Cipher([]byte("example"))

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
		panic(err.Error())
	}
	if !bytes.Equal(M, MM) {
		panic("Decryption failed to reproduce message")
	}
	fmt.Printf("Decrypted: '%s'\n", string(MM))

	// Output:
	// Encryption of 'Hello World!':
	// 00000000  f9 d1 d4 75 7b 0d 76 68  95 08 71 74 9a 87 5f 1e  |...u{.vh..qt.._.|
	// 00000010  0a 22 23 34 bd d1 5b f6  e7 21 3c f3 c9 92 6f bd  |."#4..[..!<...o.|
	// 00000020  13 59 48 86 0b ef 97 ae  c4 7f 5c 32 1e 7c 9e 66  |.YH.......\2.|.f|
	// 00000030  6c 72 72 22 2e 82 c8 70  ec f1 83 7b 13 83 ef 17  |lrr"...p...{....|
	// 00000040  09 dc 5f 08 4e a1 38 64  bb 90 59 6e d0 80 b6 f4  |.._.N.8d..Yn....|
	// 00000050  2d 4f a8 1b 48 00 f5 0d  8c 82 a6 36 71 0f c0 eb  |-O..H......6q...|
	// 00000060  6f 77 c4 61 a8 66 59 22  ea 56 75 15 8c f3 bc 5c  |ow.a.fY".Vu....\|
	// 00000070  ca 94 10 5f e8 bb 56 48  b2 2f 95 4e c6 92 ae 20  |..._..VH./.N... |
	// 00000080  81 56 69 dc ea e5 ff 03  fd 28 b4 d9 6b c7 f7 c7  |.Vi......(..k...|
	// 00000090  35 ca d5 17 de da 37 28  82 5d c6 fb 7b 3f 07 cd  |5.....7(.]..{?..|
	// 000000a0  f4 1a b5 4d b9 41 95 8a  f0 22 06 1f 5d 1a b1 2d  |...M.A..."..]..-|
	// 000000b0  2c a1 d5 38 af 13 fe 1e  b5 a0 19 37 c9 58 2d f5  |,..8.......7.X-.|
	// 000000c0  b8 1a cd c1 21 ae 84 02  88 9d d9 45              |....!......E|
	// Decrypted: 'Hello World!'
}

func ExampleEncrypt_anonSet() {

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

	// Encrypt a message with all the public keys
	M := []byte("Hello World!") // message to encrypt
	C := Encrypt(suite, rand, M, Set(X), false)
	fmt.Printf("Encryption of '%s':\n%s", string(M), hex.Dump(C))

	// Decrypt the ciphertext with the known private key
	MM, err := Decrypt(suite, C, Set(X), mine, x, false)
	if err != nil {
		panic(err.Error())
	}
	if !bytes.Equal(M, MM) {
		panic("Decryption failed to reproduce message")
	}
	fmt.Printf("Decrypted: '%s'\n", string(MM))

	// Output:
	// Encryption of 'Hello World!':
	// 00000000  3c 2e 26 55 5e 9c 59 55  68 91 5c 68 19 e3 10 6a  |<.&U^.YUh.\h...j|
	// 00000010  be 1d 8c fc 52 b1 85 98  31 a9 81 08 24 bb f0 d0  |....R...1...$...|
	// 00000020  93 91 98 a5 e9 62 40 f9  8f f4 4c 59 a5 90 1e 97  |.....b@...LY....|
	// 00000030  c8 5b 89 41 35 8f 17 ef  26 e4 bf 0f 83 2d a4 d4  |.[.A5...&....-..|
	// 00000040  a8 98 a5 8e d2 85 73 37  22 e4 0b 61 c6 f5 d3 2c  |......s7"..a...,|
	// 00000050  fd 43 3b fa a5 3f c9 97  b4 8b c2 6b 8d ec 1b 2c  |.C;..?.....k...,|
	// 00000060  8b b2 94 e1 df e5 91 ad  3f 94 a5 24 73 c2 43 86  |........?..$s.C.|
	// 00000070  1f 58 93 18 a5 bd fa bb  5e 48 7c 2d 3e 98 d8 60  |.X......^H|->..`|
	// 00000080  29 fa 47 7d 97 19 c6 ee  e0 68 7a 04 ba 02 3b da  |).G}.....hz...;.|
	// 00000090  1b 8b 87 df 47 b3 40 ed  60 c1 78 16 50 27 90 5a  |....G.@.`.x.P'.Z|
	// 000000a0  ee 8b 74 2c 00 ba 07 8b  bf 8e 72 08 a2 12 62 e8  |..t,......r...b.|
	// 000000b0  3c f5 e5 a8 bb b2 1c 27  d5 91 39 3a 24 e4 7e 55  |<......'..9:$.~U|
	// 000000c0  ef ae db d6 63 13 6b 11  1a 79 b0 de b4 19 58 ad  |....c.k..y....X.|
	// 000000d0  a9 70 8c 8b 86 35 88 fd  51 fe ea f0 cb dc 3a 00  |.p...5..Q.....:.|
	// 000000e0  31 2c 99 ba a5 f2 4b 3d  0d 7f 5c e8 c3 bf 59 fe  |1,....K=..\...Y.|
	// 000000f0  62 b1 30 84 b1 0f 06 61  0b ef 33 48 2b f6 81 a0  |b.0....a..3H+...|
	// 00000100  d6 78 fa b1 c8 53 d0 91  52 34 21 4c              |.x...S..R4!L|
	// Decrypted: 'Hello World!'
}
