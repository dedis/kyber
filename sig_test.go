package crypto

import (
	"bytes"
	"crypto/cipher"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/dedis/crypto/abstract"
	"github.com/dedis/crypto/openssl"
)

// A basic, verifiable signature
type basicSig struct {
	C abstract.Secret // challenge
	R abstract.Secret // response
}

// Returns a secret that depends on on a message and a point
func hashElGamal(suite abstract.Suite, message []byte, p abstract.Point) abstract.Secret {
	H := suite.Hash()
	H.Write(message)
	H.Write(p.Encode())

	b := H.Sum(nil)
	s := suite.Stream(b[:suite.KeyLen()])
	return suite.Secret().Pick(s)
}

// This simplified implementation of ElGamal Signatures is based on
// crypto/anon/sig.go
// The ring structure is removed and
// The anonimity set is reduced to one public key = no anonimity
func ElGamalSign(suite abstract.Suite, random cipher.Stream, message []byte,
	privateKey abstract.Secret) []byte {

	// Create random secret v and public point commitment T
	v := suite.Secret().Pick(random)
	T := suite.Point().Mul(nil, v)

	// Create challenge c based on message and T
	c := hashElGamal(suite, message, T)

	// Compute response r = v - x*c
	r := suite.Secret()
	r.Mul(privateKey, c).Sub(v, r)

	// Return verifiable signature {c, r}
	// Verifier will be able to compute v = r + x*c
	// And check that hashElgamal for T and the message == c
	buf := bytes.Buffer{}
	sig := basicSig{c, r}
	abstract.Write(&buf, &sig, suite)
	return buf.Bytes()
}

func ElGamalVerify(suite abstract.Suite, message []byte, publicKey abstract.Point,
	signatureBuffer []byte) error {

	// Decode the signature
	buf := bytes.NewBuffer(signatureBuffer)
	sig := basicSig{}
	if err := abstract.Read(buf, &sig, suite); err != nil {
		return err
	}
	r := sig.R
	c := sig.C

	// Compute base**(r + x*c) == T
	var P, T abstract.Point
	P = suite.Point()
	T = suite.Point()
	T.Add(T.Mul(nil, r), P.Mul(publicKey, c))

	// Verify that the hash based on the message and T
	// matches the challange c from the signature
	c = hashElGamal(suite, message, T)
	if !c.Equal(sig.C) {
		return errors.New("invalid signature")
	}

	return nil
}

// Example of using ElGamal
func ExampleElGamal() {
	// Crypto setup
	suite := openssl.NewAES128SHA256P256()
	rand := abstract.HashStream(suite, []byte("example"), nil)

	// Create a public/private keypair (X,x)
	x := suite.Secret().Pick(rand) // create a private key x
	X := suite.Point().Mul(nil, x) // corresponding public key X

	// Generate the signature
	M := []byte("Hello World!") // message we want to sign
	sig := ElGamalSign(suite, rand, M, x)
	fmt.Print("Signature:\n" + hex.Dump(sig))

	// Verify the signature against the correct message
	err := ElGamalVerify(suite, M, X, sig)
	if err != nil {
		panic(err.Error())
	}
	fmt.Println("Signature verified against correct message.")

	// Output:
	// Signature:
	// 00000000  ea 1b 94 c6 31 8a 90 22  2c 05 a3 e7 6f fe 31 8e  |....1..",...o.1.|
	// 00000010  e4 19 f7 3f 9e 28 b2 73  40 89 a0 1a f6 73 b1 20  |...?.(.s@....s. |
	// 00000020  c7 34 3f 18 9c ad 46 5b  f7 1e 62 b2 21 e9 91 43  |.4?...F[..b.!..C|
	// 00000030  40 33 94 ef 0b 8e e5 fa  90 02 de 9a e3 a5 ee 9e  |@3..............|
	// Signature verified against correct message.
}
