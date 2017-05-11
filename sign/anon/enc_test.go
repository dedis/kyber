package anon

import (
	"bytes"
	"fmt"
	//"testing"
	"encoding/hex"

	"github.com/dedis/crypto"
	"github.com/dedis/crypto/group/nist"
)

func ExampleEncrypt_1() {

	// Crypto setup
	suite := nist.NewAES128SHA256P256()
	rand := suite.Cipher([]byte("example"))

	// Create a public/private keypair (X[mine],x)
	X := make([]kyber.Point, 1)
	mine := 0                           // which public key is mine
	x := suite.Scalar().Pick(rand)      // create a private key x
	X[mine] = suite.Point().Mul(nil, x) // corresponding public key X

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
	// 00000000  04 23 62 b1 f9 cb f4 a2  6d 7f 3e 69 cb b6 77 ab  |.#b.....m.>i..w.|
	// 00000010  90 fc 7c db a0 c6 e8 12  f2 0a d4 40 a4 b6 c4 de  |..|........@....|
	// 00000020  9e e8 61 88 5e 50 fd 03  a9 ff 9c a3 c4 29 f7 18  |..a.^P.......)..|
	// 00000030  49 ad 31 0e f9 17 15 1e  3b 8d 0e 2f b2 c4 28 32  |I.1.....;../..(2|
	// 00000040  4a a4 16 00 51 da 5e d5  3a df f3 02 fe 77 0d 11  |J...Q.^.:....w..|
	// 00000050  27 7b 29 b4 a0 47 7a 82  8f 0a 98 4f fe fe 1e 5d  |'{)..Gz....O...]|
	// 00000060  cf d2 08 9a e5 f0 d9 3c  6b 0d 83 35 6d 15 b1 93  |.......<k..5m...|
	// 00000070  af 1d a2 17 df db 3c 2b  89 32 1b 62 1b           |......<+.2.b.|
	// Decrypted: 'Hello World!'
}

func ExampleEncrypt_anonSet() {

	// Crypto setup
	suite := nist.NewAES128SHA256P256()
	rand := suite.Cipher([]byte("example"))

	// Create an anonymity set of random "public keys"
	X := make([]kyber.Point, 3)
	for i := range X { // pick random points
		X[i], _ = suite.Point().Pick(nil, rand)
	}

	// Make just one of them an actual public/private keypair (X[mine],x)
	mine := 1                           // only the signer knows this
	x := suite.Scalar().Pick(rand)      // create a private key x
	X[mine] = suite.Point().Mul(nil, x) // corresponding public key X

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
	// 00000000  04 a4 2a cf e6 41 38 3f  d4 df 6e f4 70 05 a8 ec  |..*..A8?..n.p...|
	// 00000010  55 8a a5 a4 73 7f 34 ae  1c 50 69 fe af e4 71 01  |U...s.4..Pi...q.|
	// 00000020  51 33 a7 89 e2 f0 85 81  ce e9 bc d2 49 cb aa 9a  |Q3..........I...|
	// 00000030  55 c5 99 ad 5c a5 e4 36  e4 71 c8 c1 58 4c f7 aa  |U...\..6.q..XL..|
	// 00000040  2f 3f d2 9a ec 4b fd 85  5e 1b 7f 08 3b 82 12 75  |/?...K..^...;..u|
	// 00000050  76 e5 b2 0a 48 d1 d1 9a  5f 45 eb 57 e6 5b 4c 81  |v...H..._E.W.[L.|
	// 00000060  10 d7 98 e0 f4 ce 98 9f  94 66 28 8d c4 ff 61 3f  |.........f(...a?|
	// 00000070  2a 61 c1 31 f8 b5 60 b7  82 05 64 e4 cd 86 66 43  |*a.1..`...d...fC|
	// 00000080  f1 c1 de 23 d5 ea 19 ba  dd 27 fa 4c 66 d8 a0 19  |...#.....'.Lf...|
	// 00000090  1e 6c ea 70 b7 71 8f b5  cd 3a 49 6d c3 03 08 e0  |.l.p.q...:Im....|
	// 000000a0  4d d6 67 9c 02 67 38 c2  d8 78 0d fd 97 f2 2b 8b  |M.g..g8..x....+.|
	// 000000b0  b3 b2 ae 0d f1 2b 1c 1b  13 9d 71 75 b8           |.....+....qu.|
	// Decrypted: 'Hello World!'
}
