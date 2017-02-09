package crypto

import (
	"fmt"

	"github.com/dedis/crypto/abstract"
	"github.com/dedis/crypto/nist"
	"github.com/dedis/crypto/random"
)

func ElGamalEncrypt(suite abstract.Suite, pubkey abstract.Point, message []byte) (
	K, C abstract.Point, remainder []byte) {

	// Embed the message (or as much of it as will fit) into a curve point.
	M, remainder := suite.Point().Pick(message, random.Stream)
	fmt.Println("MESSAGE: %d", len(message))
	fmt.Printf("REMAINDER: %x", remainder)

	// ElGamal-encrypt the point to produce ciphertext (K,C).
	k := suite.Scalar().Pick(random.Stream) // ephemeral private key
	K = suite.Point().Mul(nil, k)           // ephemeral DH public key
	S := suite.Point().Mul(pubkey, k)       // ephemeral DH shared secret
	C = S.Add(S, M)                         // message blinded with secret
	return
}

func ElGamalDecrypt(suite abstract.Suite, prikey abstract.Scalar, K, C abstract.Point) (
	message []byte, err error) {

	// ElGamal-decrypt the ciphertext (K,C) to reproduce the message.
	S := suite.Point().Mul(K, prikey) // regenerate shared secret
	M := suite.Point().Sub(C, S)      // use to un-blind the message
	message, err = M.Data()           // extract the embedded data
	return
}

/*
This example illustrates how the crypto toolkit may be used
to perform "pure" ElGamal encryption,
in which the message to be encrypted is small enough to be embedded
directly within a group element (e.g., in an elliptic curve point).
For basic background on ElGamal encryption see for example
http://en.wikipedia.org/wiki/ElGamal_encryption.

Most public-key crypto libraries tend not to support embedding data in points,
in part because for "vanilla" public-key encryption you don't need it:
one would normally just generate an ephemeral Diffie-Hellman secret
and use that to seed a symmetric-key crypto algorithm such as AES,
which is much more efficient per bit and works for arbitrary-length messages.
However, in many advanced public-key crypto algorithms it is often useful
to be able to embedded data directly into points and compute with them:
as just one of many examples,
the proactively verifiable anonymous messaging scheme prototyped in Verdict
(see http://dedis.cs.yale.edu/dissent/papers/verdict-abs).

For fancier versions of ElGamal encryption implemented in this toolkit
see for example anon.Encrypt, which encrypts a message for
one of several possible receivers forming an explicit anonymity set.
*/
func Example_elGamalEncryption() {
	suite := nist.NewAES128SHA256P256()

	// Create a public/private keypair
	a := suite.Scalar().Pick(random.Stream) // Alice's private key
	A := suite.Point().Mul(nil, a)          // Alice's public key

	// ElGamal-encrypt a message using the public key.
	//	m := []byte("The quick brown fox")
	m := []byte("12345678901234567890123456789012")
	K, C, _ := ElGamalEncrypt(suite, A, m)

	// Decrypt it using the corresponding private key.
	mm, err := ElGamalDecrypt(suite, a, K, C)

	// Make sure it worked!
	if err != nil {
		panic("decryption failed: " + err.Error())
	}
	if string(mm) != string(m) {
		panic("decryption produced wrong output: " + string(mm) + " vs " + string(m))
	}
	println("Decryption succeeded: " + string(mm))

	// Output:
}
