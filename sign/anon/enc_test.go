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
	rand := suite.XOF([]byte("example"))

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
	// 00000000  de 9d f9 35 68 ed 79 28  19 0e 1e fb 0b 02 50 1b  |...5h.y(......P.|
	// 00000010  2a 18 4d 86 3a 49 a2 c7  95 38 9e 89 d4 11 06 5c  |*.M.:I...8.....\|
	// 00000020  ac 09 42 42 4a 23 1a 4b  68 92 12 21 4d f2 d3 da  |..BBJ#.Kh..!M...|
	// 00000030  03 c8 a9 37 1d 7b 5f 71  d2 8b 31 28 ea e7 cd 9e  |...7.{_q..1(....|
	// 00000040  d4 e2 20 7b eb 05 43 95  b6 8d 28 6d 4b 9c a6 f2  |.. {..C...(mK...|
	// 00000050  1c cb 68 8c 73 f8 81 15  53 16 c0 a9 9d a6 62 c2  |..h.s...S.....b.|
	// 00000060  c1 62 ca e1 d5 16 d1 94  ef c0 b5 00 33 09 91 bb  |.b..........3...|
	// 00000070  32 d5 16 ef ae ec d8 f0  26 69 51 27 4d e4 32 bc  |2.......&iQ'M.2.|
	// 00000080  bf aa 7b 97 14 c7 8e 53  9d c9 d1 6a 41 1f 86 53  |..{....S...jA..S|
	// 00000090  0b a6 55 b4 bf 86 c1 68  69 42 c4 fa c4 bf bf 10  |..U....hiB......|
	// 000000a0  87 c2 19 0a 8f 08 05 cf  d9 c1 37 e9 81 a6 65 f4  |..........7...e.|
	// 000000b0  98 72 3e 24 e9 fe 8d 2a  c9 7e 9d 64 96 4d f2 df  |.r>$...*.~.d.M..|
	// 000000c0  ff 46 d7 af 3c c6 95 a4  d9 04 6b bd              |.F..<.....k.|
	// Decrypted: 'Hello World!'
}

func ExampleEncrypt_anonSet() {

	// Crypto setup
	suite := edwards25519.NewAES128SHA256Ed25519()
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
	// 00000000  1d 94 9b 66 98 f7 66 ec  2c 66 7f 00 1a aa 90 59  |...f..f.,f.....Y|
	// 00000010  21 02 09 01 89 ae 67 a0  7e 72 46 31 5b 05 70 58  |!.....g.~rF1[.pX|
	// 00000020  d9 8a 34 f5 2d 79 d8 fc  01 44 0f 01 65 8a 4d 06  |..4.-y...D..e.M.|
	// 00000030  3e e0 45 eb f9 53 14 77  af f6 82 3c 47 13 11 02  |>.E..S.w...<G...|
	// 00000040  14 b1 ea 48 0d ad da 53  71 51 3c 99 99 f3 6e 08  |...H...SqQ<...n.|
	// 00000050  5a 4f 74 de f3 b7 25 a5  bd 00 b7 ad 15 b4 e8 a2  |ZOt...%.........|
	// 00000060  fd 71 c1 c0 50 53 54 45  ad e0 d1 b0 31 99 41 45  |.q..PSTE....1.AE|
	// 00000070  5b ec a8 25 b0 2c dd 39  18 e6 66 76 4a ca b3 a8  |[..%.,.9..fvJ...|
	// 00000080  3a 0d 2c 6f 62 2b 5f 44  9d 1d b7 cc 75 28 38 ed  |:.,ob+_D....u(8.|
	// 00000090  b6 28 ca 7d 71 bb 3a f5  d8 ab e8 1d a3 e5 1c d4  |.(.}q.:.........|
	// 000000a0  5f aa cd 96 2d 6a c6 46  39 d1 d3 df a5 06 80 41  |_...-j.F9......A|
	// 000000b0  06 0c 0e 2e 6f 0e cd 13  f2 57 66 66 df bf 5f d1  |....o....Wff.._.|
	// 000000c0  7c e4 16 94 ff 13 64 d6  80 98 63 bc 6f bc c1 90  ||.....d...c.o...|
	// 000000d0  15 be d0 eb 80 ca 4f e0  c4 ed 97 2f 8e 46 94 ce  |......O..../.F..|
	// 000000e0  c8 63 13 48 3c 32 bf 53  fb f8 bd 17 74 2c 93 93  |.c.H<2.S....t,..|
	// 000000f0  28 11 10 75 5d 69 a1 17  fe 01 90 88 1d 1d c6 44  |(..u]i.........D|
	// 00000100  46 e9 3b e0 7c f8 c8 f4  55 f0 ab c0              |F.;.|...U...|
	// Decrypted: 'Hello World!'
}
