package anon

import (
	"fmt"
	"bytes"
	//"testing"
	"encoding/hex"
	"github.com/dedis/crypto/abstract"
	"github.com/dedis/crypto/openssl"
)


func ExampleEncrypt_1() {

	// Crypto setup
	suite := openssl.NewAES128SHA256P256()
	rand := abstract.HashStream(suite, []byte("example"), nil)

	// Create a public/private keypair (X[mine],x)
	X := make([]abstract.Point,1)
	mine := 0				// which public key is mine
	x := suite.Secret().Pick(rand)		// create a private key x
	X[mine] = suite.Point().Mul(nil,x)	// corresponding public key X

	// Encrypt a message with the public key
	M := []byte("Hello World!")		// message to encrypt
	C := Encrypt(suite, rand, M, Set(X), false)
	fmt.Printf("Encryption of '%s':\n%s",string(M),hex.Dump(C))

	// Decrypt the ciphertext with the private key
	MM,err := Decrypt(suite, C, Set(X), mine, x, false)
	if err != nil {
		panic(err.Error())
	}
	if !bytes.Equal(M,MM) {
		panic("Decryption failed to reproduce message")
	}
	fmt.Printf("Decrypted: '%s'\n", string(MM))

	// Output:
	// Encryption of 'Hello World!':
	// 00000000  02 fd dc 29 56 ef d2 87  05 a6 af c2 c9 7d 6a 58  |...)V........}jX|
	// 00000010  74 96 a5 b2 10 82 2c 17  71 a4 43 db 37 14 42 48  |t.....,.q.C.7.BH|
	// 00000020  4a f3 07 99 4a e7 e9 be  60 59 9b dc 9c 75 fb 17  |J...J...`Y...u..|
	// 00000030  e7 9a ab 7b a6 b9 1b c5  9e 4d 33 92 d9 4e cd 56  |...{.....M3..N.V|
	// 00000040  ac f1 76 00 51 ad 59 e2  d5 87 62 2d 3a 5b 0d 71  |..v.Q.Y...b-:[.q|
	// 00000050  48 3e fc e2 fe cd 37 55  1a dd 8f 63 aa           |H>....7U...c.|
	// Decrypted: 'Hello World!'
}

func ExampleEncrypt_anonSet() {

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

	// Encrypt a message with all the public keys
	M := []byte("Hello World!")		// message to encrypt
	C := Encrypt(suite, rand, M, Set(X), false)
	fmt.Printf("Encryption of '%s':\n%s",string(M),hex.Dump(C))

	// Decrypt the ciphertext with the known private key
	MM,err := Decrypt(suite, C, Set(X), mine, x, false)
	if err != nil {
		panic(err.Error())
	}
	if !bytes.Equal(M,MM) {
		panic("Decryption failed to reproduce message")
	}
	fmt.Printf("Decrypted: '%s'\n", string(MM))

	// Output:
	// Encryption of 'Hello World!':
	// 00000000  02 c1 f8 24 2c e6 bd 39  65 7b 20 3b 07 f9 56 08  |...$,..9e{ ;..V.|
	// 00000010  19 61 a4 67 2c ea f3 49  fa f3 e4 59 4d 78 25 80  |.a.g,..I...YMx%.|
	// 00000020  e2 3f c7 00 99 d3 ac ea  6b df a9 6a 45 c5 fb be  |.?......k..jE...|
	// 00000030  6e ae 71 fb cd 3b f5 fd  96 3c d7 ee d7 cd ad 7a  |n.q..;...<.....z|
	// 00000040  39 d5 9c d8 c2 24 1f 51  ab c1 04 e8 19 c1 41 23  |9....$.Q......A#|
	// 00000050  b2 84 c6 3c 0f fd 3d 22  91 60 c1 3d f9 5a ab b2  |...<..=".`.=.Z..|
	// 00000060  05 56 7e bb b4 6e ae 02  ce 50 47 3a f2 4b b4 48  |.V~..n...PG:.K.H|
	// 00000070  08 fe 58 11 84 51 af f2  46 46 d7 a0 28 07 e6 df  |..X..Q..FF..(...|
	// 00000080  af e0 63 af a1 70 54 35  09 66 5f e1 ba 26 fa 5b  |..c..pT5.f_..&.[|
	// 00000090  54 46 50 12 53 f2 bf b2  e9 f6 4d 5c 8a           |TFP.S.....M\.|
	// Decrypted: 'Hello World!'
}

