package anon

import (
	"bytes"
	"encoding/hex"
	"fmt"

	"github.com/dedis/kyber"
	"github.com/dedis/kyber/group/edwards25519"
	"github.com/dedis/kyber/xof/blake"
)

func ExampleEncrypt_one() {
	// Crypto setup: Get a suite which returns a predictable
	// random number stream for this example.
	// In production, simply use edwards25519.NewBlakeSHA256Ed25519()
	suite := edwards25519.NewBlakeSHA256Ed25519WithRand(blake.New(nil))

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
	// 00000000  8a 5d a9 e1 b1 8f c8 ed  65 10 b8 0f 06 97 48 c8  |.]......e.....H.|
	// 00000010  26 8e a3 11 fd 68 24 7e  a1 46 28 82 8d 83 02 bf  |&....h$~.F(.....|
	// 00000020  87 9a 4f a9 fc e4 1c 96  02 b7 09 03 c2 a4 b5 26  |..O............&|
	// 00000030  9b 15 61 de 0c f4 64 46  19 99 46 63 26 07 9a 88  |..a...dF..Fc&...|
	// 00000040  0f 9f 39 71 1c 2f f8 23  28 bd 42 7d d5 ca 9e 57  |..9q./.#(.B}...W|
	// 00000050  40 86 33 8e ef 47 11 b6  d9 9b ed dd              |@.3..G......|
	// Decrypted: 'Hello World!'
}

func ExampleEncrypt_anonSet() {
	// Crypto setup: Get a suite which returns a predictable
	// random number stream for this example.
	// In production, simply use edwards25519.NewBlakeSHA256Ed25519()
	suite := edwards25519.NewBlakeSHA256Ed25519WithRand(blake.New(nil))

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
	// 00000000  f2 bd 06 25 9b 8b 6f dd  8c 2e 46 f6 2a 59 bd 34  |...%..o...F.*Y.4|
	// 00000010  ea d5 64 14 ed c9 b3 a6  16 63 41 45 58 7d 28 13  |..d......cAEX}(.|
	// 00000020  e2 ff a9 bf 88 36 a0 e3  df 47 d3 e8 9d 44 90 4a  |.....6...G...D.J|
	// 00000030  ce 7c 79 4a af 6a c3 ee  81 37 03 93 e5 87 d8 32  |.|yJ.j...7.....2|
	// 00000040  c8 b9 d8 89 60 4a 5c 7b  eb 8e 15 12 01 d7 c0 03  |....`J\{........|
	// 00000050  c7 9d 72 7a 0f 40 30 65  40 4c 31 f4 8d 3a 7c 81  |..rz.@0e@L1..:|.|
	// 00000060  59 30 09 a4 e0 c1 22 2e  0e 3b 1f a6 b7 b3 5a e4  |Y0...."..;....Z.|
	// 00000070  bd 3a cd 88 d4 b4 b8 31  22 ad 91 5d 5a b5 43 ef  |.:.....1"..]Z.C.|
	// 00000080  ef cb 56 81 0f 9f 6a 84  60 a1 3d 4c 9b a7 40 ce  |..V...j.`.=L..@.|
	// 00000090  6b 52 27 1b 60 5b 8a 40  35 5e 18 0e              |kR'.`[.@5^..|
	// Decrypted: 'Hello World!'
}
