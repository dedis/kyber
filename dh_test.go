package crypto

import (
	"gopkg.in/dedis/crypto.v0/nist"
	"gopkg.in/dedis/crypto.v0/random"
)

/*
This example illustrates how to use the crypto toolkit's abstract group API
to perform basic Diffie-Hellman key exchange calculations,
using the NIST-standard P256 elliptic curve in this case.
Any other suitable elliptic curve or other cryptographic group may be used
simply by changing the first line that picks the suite.
*/
func Example_diffieHellman() {

	// Crypto setup: NIST-standardized P256 curve with AES-128 and SHA-256
	suite := nist.NewAES128SHA256P256()

	// Alice's public/private keypair
	a := suite.Scalar().Pick(random.Stream) // Alice's private key
	A := suite.Point().Mul(nil, a)          // Alice's public key

	// Bob's public/private keypair
	b := suite.Scalar().Pick(random.Stream) // Alice's private key
	B := suite.Point().Mul(nil, b)          // Alice's public key

	// Assume Alice and Bob have securely obtained each other's public keys.

	// Alice computes their shared secret using Bob's public key.
	SA := suite.Point().Mul(B, a)

	// Bob computes their shared secret using Alice's public key.
	SB := suite.Point().Mul(A, b)

	// They had better be the same!
	if !SA.Equal(SB) {
		panic("Diffie-Hellman key exchange didn't work")
	}
	println("Shared secret: " + SA.String())

	// Output:
}
