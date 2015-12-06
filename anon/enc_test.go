package anon

import (
	"bytes"
	"fmt"
	//"testing"
	"encoding/hex"
	"github.com/dedis/crypto/abstract"
	"github.com/dedis/crypto/suite"
)

func ExampleEncrypt_1() {

	// Crypto setup
	suite := suite.Default(nil)
	rand := suite.Cipher([]byte("example"))

	// Create a public/private keypair (X[mine],x)
	X := make([]abstract.Point, 1)
	mine := 0                          // which public key is mine
	x := suite.Scalar().Random(rand)   // create a private key x
	X[mine] = suite.Point().BaseMul(x) // corresponding public key X

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
	// 00000000  80 63 15 19 7f 91 5f 81  94 40 3b a0 7b cd b2 53  |.c...._..@;.{..S|
	// 00000010  39 e6 09 e8 dd 6b 33 9a  4a fa cc 6b b5 aa ef 52  |9....k3.J..k...R|
	// 00000020  6d 0f 62 25 4f e8 3a 83  55 18 1a c3 5f 88 fc 1c  |m.b%O.:.U..._...|
	// 00000030  1e 97 dc 03 9d 3b 3e a4  07 08 0a 92 6c 10 9a 09  |.....;>.....l...|
	// 00000040  a6 51 09 9f 3c b6 65 0e  1d 9e 06 51 11 b2 01 1c  |.Q..<.e....Q....|
	// 00000050  84 43 ab fd 4a 32 e4 b2  1d d9 61 da              |.C..J2....a.|
	// Decrypted: 'Hello World!'
}

func ExampleEncrypt_anonSet() {

	// Crypto setup
	suite := suite.Default(nil)
	rand := suite.Cipher([]byte("example"))

	// Create an anonymity set of random "public keys"
	X := make([]abstract.Point, 3)
	for i := range X { // pick random points
		X[i] = suite.Point().Random(rand)
	}

	// Make just one of them an actual public/private keypair (X[mine],x)
	mine := 1                          // only the signer knows this
	x := suite.Scalar().Random(rand)   // create a private key x
	X[mine] = suite.Point().BaseMul(x) // corresponding public key X

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
	// 00000000  62 f9 88 18 91 74 d4 29  37 3c aa 51 53 75 e7 96  |b....t.)7<.QSu..|
	// 00000010  cf ea 66 18 7c ce 47 c3  e3 73 5e 36 d1 6b fb e0  |..f.|.G..s^6.k..|
	// 00000020  40 75 1e 24 9d 4e dd cc  3e 65 0b 41 c4 5b ac 3e  |@u.$.N..>e.A.[.>|
	// 00000030  4f 6c de 7c 5a d0 e4 b7  87 0b c6 4c 06 bf c9 7c  |Ol.|Z......L...||
	// 00000040  be 8a 57 7e 0a 80 24 b8  13 b6 6e 1a e6 a3 a3 4d  |..W~..$...n....M|
	// 00000050  cd c7 84 7c 89 ca 2d 24  31 e1 4a 2a 90 af 52 d8  |...|..-$1.J*..R.|
	// 00000060  98 82 4a df d8 b0 56 13  55 c9 d6 e4 11 1c 1a 71  |..J...V.U......q|
	// 00000070  bf 75 2a a4 2e d6 16 e4  59 da 4f e9 5e 21 d4 97  |.u*.....Y.O.^!..|
	// 00000080  cf 1d 70 85 84 52 d0 80  b4 5f fb a2 c1 dd 2d d6  |..p..R..._....-.|
	// 00000090  65 12 29 1a d1 07 88 2b  87 36 99 8f              |e.)....+.6..|
	// Decrypted: 'Hello World!'
}
