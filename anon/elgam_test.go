package anon

import (
	"fmt"
	"bytes"
	"testing"
	"encoding/hex"
	"github.com/dedis/crypto/abstract"
)

func ExampleSign_1() {

	// Crypto setup
	suite := openssl.NewAES128SHA256P256()
	rand := abstract.HashStream(suite, []byte("example"), nil)

	// Create a public/private keypair (X,x)
	x := suite.Secret().Pick(rand)		// create a private key x
	X = suite.Point().Mul(nil,x)		// corresponding public key X

	// Generate the signature
	M := []byte("Hello World!")		// message we want to sign
	sig := Sign(suite, rand, M, X, x)
	fmt.Print("Signature:\n"+hex.Dump(sig))

	// Verify the signature against the correct message
	err := Verify(suite, M, X, sig)
	if err != nil {
		panic(err.Error())
	}
	fmt.Println("Signature verified against correct message.")

	// Verify the signature against the wrong message
	BAD := []byte("Goodbye world!")
	err = Verify(suite, BAD, X, sig)
	if err == nil {
		panic("Signature verified against wrong message!?")
	}
	fmt.Println("Verifying against wrong message: "+err.Error())
}