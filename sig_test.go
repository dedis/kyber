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
	c := suite.Cipher(p.Encode())
	c.Message(nil, nil, message)
	return suite.Secret().Pick(c)
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
	rand := suite.Cipher([]byte("example"))

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
	// 00000000  4f 52 f0 66 5f ed a4 2e  e1 e5 35 ed f3 d4 d9 3e  |OR.f_.....5....>|
	// 00000010  62 69 1e 96 65 34 a1 f2  d8 d9 cc 31 4f c9 39 c6  |bi..e4.....1O.9.|
	// 00000020  c8 09 93 0f 25 8d 2a e3  3a 36 ae bf 27 35 5b 2c  |....%.*.:6..'5[,|
	// 00000030  7a 92 9b a8 93 83 ee 05  f4 35 6a c7 bd fa e4 60  |z........5j....`|
	// Signature verified against correct message.
}
