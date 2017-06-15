package anon

import (
	"bytes"
	"fmt"
	//"testing"
	"encoding/hex"

	"gopkg.in/dedis/kyber.v1"
	"gopkg.in/dedis/kyber.v1/group/edwards25519"
)

func ExampleEncrypt_1() {

	// Crypto setup
	suite := edwards25519.NewAES128SHA256Ed25519(false)
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
	// 00000000  27 fd 13 c3 6e e6 df a5  00 aa 0c 93 a7 b8 21 4b  |'...n.........!K|
	// 00000010  a5 cf 26 c2 a0 99 68 b0  a0 36 9d 7a de 92 95 7a  |..&...h..6.z...z|
	// 00000020  40 9d b9 72 10 29 24 8a  71 10 df 3a a8 36 22 7e  |@..r.)$.q..:.6"~|
	// 00000030  53 16 52 2f 92 95 75 76  0c db 33 37 7d 39 c2 66  |S.R/..uv..37}9.f|
	// 00000040  b4 73 4d 18 31 75 0e 7d  11 05 c5 16 be b6 56 02  |.sM.1u.}......V.|
	// 00000050  0b b0 67 5f 86 e2 69 f6  b8 ef 28 b9              |..g_..i...(.|
	// Decrypted: 'Hello World!'

}

func ExampleEncrypt_anonSet() {

	// Crypto setup
	suite := edwards25519.NewAES128SHA256Ed25519(false)
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
	// 00000000  b6 8f 24 dc d3 c0 86 67  42 1d c3 c8 5a 28 62 4d  |..$....gB...Z(bM|
	// 00000010  86 3b c9 69 7c 88 7f 52  9e b3 93 25 2d e6 58 0e  |.;.i|..R...%-.X.|
	// 00000020  1e 9c c2 1b 74 cf 0e 01  4b 1c c8 9f df eb 15 18  |....t...K.......|
	// 00000030  91 d8 d1 04 0e 5b d0 5e  50 bd aa ce 66 42 a8 f8  |.....[.^P...fB..|
	// 00000040  9e 43 8e 5f 32 5f 07 7c  d7 9d d8 3c 2e d9 3c 4f  |.C._2_.|...<..<O|
	// 00000050  86 03 2c 35 21 d8 a0 2c  84 42 05 e4 bb 9e 83 e9  |..,5!..,.B......|
	// 00000060  5a 12 77 dc 06 ca 09 79  5b 09 42 3e c2 6e 94 13  |Z.w....y[.B>.n..|
	// 00000070  0a 8f 6c f7 42 34 3e 3a  eb 0d 9c 2d 20 19 86 1f  |..l.B4>:...- ...|
	// 00000080  55 fd 56 ca 1d 92 f8 1e  e1 f3 39 4d bf 02 7c 14  |U.V.......9M..|.|
	// 00000090  4a d4 67 90 74 34 c8 4e  0c b5 cf ef              |J.g.t4.N....|
	// Decrypted: 'Hello World!'
}
