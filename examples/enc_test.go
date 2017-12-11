package examples

import (
	"fmt"

	"github.com/dedis/kyber"
	"github.com/dedis/kyber/group/edwards25519"
	"github.com/dedis/kyber/util/random"
)

func ElGamalEncrypt(group kyber.Group, pubkey kyber.Point, message []byte) (
	K, C kyber.Point, remainder []byte) {

	// Embed the message (or as much of it as will fit) into a curve point.
	M := group.Point().Embed(message, random.New())
	max := group.Point().EmbedLen()
	if max > len(message) {
		max = len(message)
	}
	remainder = message[max:]
	// ElGamal-encrypt the point to produce ciphertext (K,C).
	k := group.Scalar().Pick(random.New()) // ephemeral private key
	K = group.Point().Mul(k, nil)          // ephemeral DH public key
	S := group.Point().Mul(k, pubkey)      // ephemeral DH shared secret
	C = S.Add(S, M)                        // message blinded with secret
	return
}

func ElGamalDecrypt(group kyber.Group, prikey kyber.Scalar, K, C kyber.Point) (
	message []byte, err error) {

	// ElGamal-decrypt the ciphertext (K,C) to reproduce the message.
	S := group.Point().Mul(prikey, K) // regenerate shared secret
	M := group.Point().Sub(C, S)      // use to un-blind the message
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
	suite := edwards25519.NewBlakeSHA256Ed25519()

	// Create a public/private keypair
	a := suite.Scalar().Pick(suite.RandomStream()) // Alice's private key
	A := suite.Point().Mul(a, nil)                 // Alice's public key

	// ElGamal-encrypt a message using the public key.
	m := []byte("The quick brown fox")
	K, C, _ := ElGamalEncrypt(suite, A, m)

	// Decrypt it using the corresponding private key.
	mm, err := ElGamalDecrypt(suite, a, K, C)

	// Make sure it worked!
	if err != nil {
		fmt.Println("decryption failed: " + err.Error())
	}
	if string(mm) != string(m) {
		fmt.Println("decryption produced wrong output: " + string(mm))
	}
	fmt.Println("Decryption succeeded: " + string(mm))

	// Output:
	// Decryption succeeded: The quick brown fox
}
