package anon

import (
	"fmt"
	"testing"
	"encoding/hex"
	"github.com/dedis/crypto/abstract"
	"github.com/dedis/crypto/openssl"
)

// testing ElGam via simplified ExampleSign_1 in sig.go
func TestElGam( t *testing.T) {
	// Crypto setup
	suite := openssl.NewAES128SHA256P256()
	rand := abstract.HashStream(suite, []byte("example"), nil)

	// Create a public/private keypair (X,x)
	x := suite.Secret().Pick(rand)		// create a private key x
	X := suite.Point().Mul(nil,x)		// corresponding public key X

	// Generate the signature
	M := []byte("Hello World!")		// message we want to sign
	sig := SignElGam(suite, rand, M, X, x)
	fmt.Print("Signature:\n"+hex.Dump(sig))

	// Verify the signature against the correct message
	err := VerifyElGam(suite, M, X, sig)
	if err != nil {
		t.Error(err.Error())
		// panic(err.Error())
	}
	fmt.Println("Signature verified against correct message.")

	// Verify the signature against the wrong message
	BAD := []byte("Goodbye world!")
	err = VerifyElGam(suite, BAD, X, sig)
	if err == nil {
		t.Error("Signature verified against wrong message!?")
		// panic("Signature verified against wrong message!?")
	}
	fmt.Println("Verifying against wrong message: "+err.Error())

	// Output:
	// Signature:
	// 00000000  aa ed 0d ac 14 0d 60 d9  88 8b 3c c2 86 0b f5 79  |......`...<....y|
	// 00000010  bd 1e ec 0c e8 03 83 44  9b 3b 64 c5 14 4e 87 c4  |.......D.;d..N..|
	// 00000020  58 8c a0 be c8 4c 15 c9  83 56 70 60 23 7a bd 2a  |X....L...Vp`#z.*|
	// 00000030  1b 64 f1 71 09 ea 0f b3  0d 3d 05 a7 c0 95 c0 94  |.d.q.....=......|
	// Signature verified against correct message.
	// Verifying against wrong message: invalid signature
}

// testing ElGam, ElGam  generated signature, sig.go verified signature
func TestElGamAgainstSig1( t *testing.T) {
	// Crypto setup
	suite := openssl.NewAES128SHA256P256()
	rand := abstract.HashStream(suite, []byte("example"), nil)

	// Create a public/private keypair (X,x)
	X := make([]abstract.Point,1)
	x := suite.Secret().Pick(rand)		// create a private key x
	X[0] = suite.Point().Mul(nil,x)		// corresponding public key X

	// Generate the signature
	M := []byte("Hello World!")		// message we want to sign
	sig := SignElGam(suite, rand, M, X[0], x)
	fmt.Print("Signature:\n"+hex.Dump(sig))

	// Verify the signature against the correct message
	tag,err := Verify(suite, M, Set(X), nil, sig)
	if err != nil {
		t.Error(err.Error())
		panic(err.Error())
	}
	if tag == nil || len(tag) != 0 {
		panic("Verify returned wrong tag")
	}
	fmt.Println("Signature verified against correct message.")

	// Verify the signature against the wrong message
	BAD := []byte("Goodbye world!")
	tag,err = Verify(suite, BAD, Set(X), nil, sig)
	if err == nil || tag != nil {
		t.Error("Signature verified against wrong message!?")
		panic("Signature verified against wrong message!?")
	}
	fmt.Println("Verifying against wrong message: "+err.Error())

	// Output:
	// Signature:
	// 00000000  aa ed 0d ac 14 0d 60 d9  88 8b 3c c2 86 0b f5 79  |......`...<....y|
	// 00000010  bd 1e ec 0c e8 03 83 44  9b 3b 64 c5 14 4e 87 c4  |.......D.;d..N..|
	// 00000020  58 8c a0 be c8 4c 15 c9  83 56 70 60 23 7a bd 2a  |X....L...Vp`#z.*|
	// 00000030  1b 64 f1 71 09 ea 0f b3  0d 3d 05 a7 c0 95 c0 94  |.d.q.....=......|
	// Signature verified against correct message.
	// Verifying against wrong message: invalid signature
}

// testing ElGam, sig.go generated signature, ElGam verified signature
func TestElGamAgainstSig2( t *testing.T) {
	// Crypto setup
	suite := openssl.NewAES128SHA256P256()
	rand := abstract.HashStream(suite, []byte("example"), nil)

	// Create a public/private keypair (X[mine],x)
	X := make([]abstract.Point,1)
	mine := 0				// which public key is mine
	x := suite.Secret().Pick(rand)		// create a private key x
	X[mine] = suite.Point().Mul(nil,x)	// corresponding public key X

	// Generate the signature
	M := []byte("Hello World!")		// message we want to sign
	sig := Sign(suite, rand, M, Set(X), nil, mine, x)
	fmt.Print("Signature:\n"+hex.Dump(sig))

	// Verify the signature against the correct message
	err := VerifyElGam(suite, M, X[mine], sig)
	if err != nil {
		t.Error(err.Error())
		// panic(err.Error())
	}
	fmt.Println("Signature verified against correct message.")

	// Verify the signature against the wrong message
	BAD := []byte("Goodbye world!")
	err = VerifyElGam(suite, BAD, X[mine], sig)
	if err == nil {
		t.Error("Signature verified against wrong message!?")
		// panic("Signature verified against wrong message!?")
	}
	fmt.Println("Verifying against wrong message: "+err.Error())

	// Output:
	// Signature:
	// 00000000  aa ed 0d ac 14 0d 60 d9  88 8b 3c c2 86 0b f5 79  |......`...<....y|
	// 00000010  bd 1e ec 0c e8 03 83 44  9b 3b 64 c5 14 4e 87 c4  |.......D.;d..N..|
	// 00000020  58 8c a0 be c8 4c 15 c9  83 56 70 60 23 7a bd 2a  |X....L...Vp`#z.*|
	// 00000030  1b 64 f1 71 09 ea 0f b3  0d 3d 05 a7 c0 95 c0 94  |.d.q.....=......|
	// Signature verified against correct message.
	// Verifying against wrong message: invalid signature
}
