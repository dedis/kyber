package anon

import (
	"bytes"
	"encoding/hex"
	"fmt"

	"github.com/dedis/kyber"
	"github.com/dedis/kyber/group/edwards25519"
	"github.com/dedis/kyber/xof/blake2xb"
)

func ExampleEncrypt_one() {
	// Crypto setup: Get a suite which returns a predictable
	// random number stream for this example.
	// In production, simply use edwards25519.NewBlakeSHA256Ed25519()
	suite := edwards25519.NewBlakeSHA256Ed25519WithRand(blake2xb.New(nil))

	// Create a public/private keypair (X[mine],x)
	X := make([]kyber.Point, 1)
	mine := 0                                      // which public key is mine
	x := suite.Scalar().Pick(suite.RandomStream()) // create a private key x
	X[mine] = suite.Point().Mul(x, nil)            // corresponding public key X

	// Encrypt a message with the public key
	M := []byte("Hello World!")
	C := Encrypt(suite, M, Set(X), false)
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
	// 00000000  82 ea 76 3b 11 5f ee b2  ac 08 62 af 84 52 1c 0c  |..v;._....b..R..|
	// 00000010  e9 1d 7d 15 b5 44 2e 65  cb 19 45 49 45 f0 10 8f  |..}..D.e..EIE...|
	// 00000020  7b c3 0c 03 22 67 9f 54  9a 44 52 a9 bb ac 51 07  |{..."g.T.DR...Q.|
	// 00000030  c8 98 9d 5d dd 54 11 e3  9f a9 7c 44 b5 c7 bf f8  |...].T....|D....|
	// 00000040  23 af 58 fb 5f 40 2d 92  e9 63 fe 71 13 33 e0 ce  |#.X._@-..c.q.3..|
	// 00000050  65 83 88 45 3c 88 3f bd  2f bd 3a 03              |e..E<.?./.:.|
	// Decrypted: 'Hello World!'
}

func ExampleEncrypt_anonSet() {
	// Crypto setup: Get a suite which returns a predictable
	// random number stream for this example.
	// In production, simply use edwards25519.NewBlakeSHA256Ed25519()
	suite := edwards25519.NewBlakeSHA256Ed25519WithRand(blake2xb.New(nil))

	// Create an anonymity set of random "public keys"
	X := make([]kyber.Point, 3)
	for i := range X { // pick random points
		X[i] = suite.Point().Pick(suite.RandomStream())
	}

	// Make just one of them an actual public/private keypair (X[mine],x)
	mine := 1                                      // only the signer knows this
	x := suite.Scalar().Pick(suite.RandomStream()) // create a private key x
	X[mine] = suite.Point().Mul(x, nil)            // corresponding public key X

	// Encrypt a message with all the public keys
	M := []byte("Hello World!") // message to encrypt
	C := Encrypt(suite, M, Set(X), false)
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
	// 00000000  c3 c2 10 b2 dc 66 58 f7  6d 3b 65 a4 c6 b9 2a d5  |.....fX.m;e...*.|
	// 00000010  3f 8d f8 68 41 92 c7 84  ef 7d a1 6c 59 89 d0 bc  |?..hA....}.lY...|
	// 00000020  ea 60 08 5f f4 ab 35 48  08 be 85 be e8 58 fa 84  |.`._..5H.....X..|
	// 00000030  ea 97 d0 57 10 01 c4 bc  9f 65 18 a6 4c e1 d2 b9  |...W.....e..L...|
	// 00000040  df 81 4a 63 da 92 56 49  20 f4 8a 9e ff d5 52 42  |..Jc..VI .....RB|
	// 00000050  8d bd 28 b7 b3 61 3b 1c  89 12 cc 4b 8e d9 c0 7b  |..(..a;....K...{|
	// 00000060  7d f5 d8 53 c9 9f cf e9  cc 68 35 d3 e8 bc 21 b1  |}..S.....h5...!.|
	// 00000070  01 7d ae b4 b0 eb 5b c0  ad b7 c7 b6 c5 9c 01 df  |.}....[.........|
	// 00000080  7c 35 28 21 1a 04 94 de  ba 0f 42 6e b9 9f bb c5  ||5(!......Bn....|
	// 00000090  1e 37 4d ab 06 63 d2 37  97 d5 45 2a              |.7M..c.7..E*|
	// Decrypted: 'Hello World!'
}
