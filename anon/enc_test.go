package anon

import (
	"fmt"
	"bytes"
	//"testing"
	"encoding/hex"
	"github.com/dedis/crypto"
	"github.com/dedis/crypto/openssl"
)


func ExampleEncrypt_1() {

	// Crypto setup
	suite := openssl.NewAES128SHA256P256()
	rand := crypto.HashStream(suite, []byte("example"), nil)

	// Create a public/private keypair (X[mine],x)
	X := make([]crypto.Point,1)
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
	// 00000000  02 a7 88 0a 50 7e 71 48  03 0d a8 6c 31 f7 01 ed  |....P~qH...l1...|
	// 00000010  c5 ea 92 5a b3 35 85 42  43 ec b2 72 1c 50 10 88  |...Z.5.BC..r.P..|
	// 00000020  fe 51 08 ff 5d c1 18 90  63 8d 55 91 04 2c 01 00  |.Q..]...c.U..,..|
	// 00000030  22 53 46 92 70 af 4b 0e  31 19 77 4a b1 0c 47 eb  |"SF.p.K.1.wJ..G.|
	// 00000040  d7 36 42 a8 18 7a 64 91  c9 ee 6f e5 de 4f 45 f4  |.6B..zd...o..OE.|
	// 00000050  f5 0f 7c 88 1c 73 2e 0f  cb 03 9f 99 ac           |..|..s.......|
	// Decrypted: 'Hello World!'
}

func ExampleEncrypt_anonSet() {

	// Crypto setup
	suite := openssl.NewAES128SHA256P256()
	rand := crypto.HashStream(suite, []byte("example"), nil)

	// Create an anonymity set of random "public keys"
	X := make([]crypto.Point,3)
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
	// 00000000  02 6c 80 85 22 19 be eb  0a d1 58 d3 20 95 56 4d  |.l..".....X. .VM|
	// 00000010  15 77 e1 52 ea c4 d9 86  dd 45 b0 63 ba ef 1b b8  |.w.R.....E.c....|
	// 00000020  4b c0 fe 5f f3 69 99 16  76 2e 2b 74 13 b1 d5 15  |K.._.i..v.+t....|
	// 00000030  91 8f ad ba b1 b4 ca 2a  07 2d a7 f0 8b 26 f8 f6  |.......*.-...&..|
	// 00000040  9d 9a 01 e5 8f a5 2f 2d  e4 ca 0b 84 46 05 8c 25  |....../-....F..%|
	// 00000050  19 c3 14 af 68 75 fa e1  45 62 cf 2f b6 49 2c 68  |....hu..Eb./.I,h|
	// 00000060  6d 0e a6 56 7c 84 5b 4e  71 15 46 c3 e5 de 8a 4c  |m..V|.[Nq.F....L|
	// 00000070  e5 cb 2a f4 6d e0 0d 42  3a da c2 8b 89 86 17 bd  |..*.m..B:.......|
	// 00000080  4a 2a 3d 8a 41 05 14 12  01 af f9 0c 7e 3d 71 72  |J*=.A.......~=qr|
	// 00000090  1b 04 0b 2f 5e 2a 65 51  2e 23 a5 ba 08           |.../^*eQ.#...|
	// Decrypted: 'Hello World!'
}

