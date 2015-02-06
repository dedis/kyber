package anon

import (
	"bytes"
	"fmt"
	//"testing"
	"encoding/hex"
	"github.com/dedis/crypto/abstract"
	"github.com/dedis/crypto/openssl"
)

func ExampleEncrypt_1() {

	// Crypto setup
	suite := openssl.NewAES128SHA256P256()
	rand := suite.Cipher([]byte("example"))

	// Create a public/private keypair (X[mine],x)
	X := make([]abstract.Point, 1)
	mine := 0                           // which public key is mine
	x := suite.Secret().Pick(rand)      // create a private key x
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
	// 00000000  02 23 62 b1 f9 cb f4 a2  6d 7f 3e 69 cb b6 77 ab  |.#b.....m.>i..w.|
	// 00000010  90 fc 7c db a0 c6 e8 12  f2 0a d4 40 a4 b6 c4 de  |..|........@....|
	// 00000020  9e 5a 8a 1d 5b e4 96 f7  a9 cb 78 4e 8e ee 23 6b  |.Z..[.....xN..#k|
	// 00000030  f3 5c fc 85 95 59 b0 81  72 bc e2 7b bf d5 1f c1  |.\...Y..r..{....|
	// 00000040  5f d2 08 9a e5 f0 d9 3c  6b 0d 83 35 6d 15 b1 93  |_......<k..5m...|
	// 00000050  af 1d a2 17 df db 3c 2b  89 32 1b 62 1b           |......<+.2.b.|
	// Decrypted: 'Hello World!'
}

func ExampleEncrypt_anonSet() {

	// Crypto setup
	suite := openssl.NewAES128SHA256P256()
	rand := suite.Cipher([]byte("example"))

	// Create an anonymity set of random "public keys"
	X := make([]abstract.Point, 3)
	for i := range X { // pick random points
		X[i], _ = suite.Point().Pick(nil, rand)
	}

	// Make just one of them an actual public/private keypair (X[mine],x)
	mine := 1                           // only the signer knows this
	x := suite.Secret().Pick(rand)      // create a private key x
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
	// 00000000  02 c2 6c b8 1b 87 94 1d  71 c8 50 63 75 e1 80 5e  |..l.....q.Pcu..^|
	// 00000010  b2 b8 1a d6 10 be 1a c6  35 bf b9 c0 cb af 67 d0  |........5.....g.|
	// 00000020  c1 38 04 f2 7e 70 c0 0e  ce 2a 3e 8d a4 1a 8f d8  |.8..~p...*>.....|
	// 00000030  c6 ca 2d 81 2a 50 d0 4e  96 74 2a 8b 44 22 12 5f  |..-.*P.N.t*.D"._|
	// 00000040  57 73 d1 1f a3 a9 21 96  2e e3 bd 77 bf 3b 3f a7  |Ws....!....w.;?.|
	// 00000050  b7 aa 91 37 7d d6 12 c6  73 db 9f 01 fd b3 f6 b6  |...7}...s.......|
	// 00000060  82 cf 0d e1 5c 57 ac 8e  82 72 20 06 af 70 90 15  |....\W...r ..p..|
	// 00000070  cb 5c f5 87 8d 39 3a 29  66 8e df 62 3d b0 ba fa  |.\...9:)f..b=...|
	// 00000080  3f 38 83 eb 92 62 fd 33  cb b0 76 ae e1 af 60 f3  |?8...b.3..v...`.|
	// 00000090  7b ba 1d ef b0 2a 7a 19  a5 92 23 fa d3           |{....*z...#..|
	// Decrypted: 'Hello World!'
}
