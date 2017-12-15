package examples

import (
	"bytes"
	"crypto/cipher"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/dedis/kyber"
	"github.com/dedis/kyber/group/edwards25519"
)

type Suite interface {
	kyber.Group
	kyber.Encoding
	kyber.XOFFactory
}

// A basic, verifiable signature
type basicSig struct {
	C kyber.Scalar // challenge
	R kyber.Scalar // response
}

// Returns a secret that depends on on a message and a point
func hashSchnorr(suite Suite, message []byte, p kyber.Point) kyber.Scalar {
	pb, _ := p.MarshalBinary()
	c := suite.XOF(pb)
	c.Write(message)
	return suite.Scalar().Pick(c)
}

// This simplified implementation of Schnorr Signatures is based on
// crypto/anon/sig.go
// The ring structure is removed and
// The anonimity set is reduced to one public key = no anonimity
func SchnorrSign(suite Suite, random cipher.Stream, message []byte,
	privateKey kyber.Scalar) []byte {

	// Create random secret v and public point commitment T
	v := suite.Scalar().Pick(random)
	T := suite.Point().Mul(v, nil)

	// Create challenge c based on message and T
	c := hashSchnorr(suite, message, T)

	// Compute response r = v - x*c
	r := suite.Scalar()
	r.Mul(privateKey, c).Sub(v, r)

	// Return verifiable signature {c, r}
	// Verifier will be able to compute v = r + x*c
	// And check that hashElgamal for T and the message == c
	buf := bytes.Buffer{}
	sig := basicSig{c, r}
	_ = suite.Write(&buf, &sig)
	return buf.Bytes()
}

func SchnorrVerify(suite Suite, message []byte, publicKey kyber.Point,
	signatureBuffer []byte) error {

	// Decode the signature
	buf := bytes.NewBuffer(signatureBuffer)
	sig := basicSig{}
	if err := suite.Read(buf, &sig); err != nil {
		return err
	}
	r := sig.R
	c := sig.C

	// Compute base**(r + x*c) == T
	var P, T kyber.Point
	P = suite.Point()
	T = suite.Point()
	T.Add(T.Mul(r, nil), P.Mul(c, publicKey))

	// Verify that the hash based on the message and T
	// matches the challange c from the signature
	c = hashSchnorr(suite, message, T)
	if !c.Equal(sig.C) {
		return errors.New("invalid signature")
	}

	return nil
}

// This example shows how to perform a simple Schnorr signature. Please, use this
// example as a reference to understand the abstraction only. There is a
// `sign/schnorr` package which provides Schnorr signatures functionality in a
// more secure manner.
func Example_schnorr() {
	// Crypto setup
	suite := edwards25519.NewBlakeSHA256Ed25519()
	rand := suite.XOF([]byte("example"))

	// Create a public/private keypair (X,x)
	x := suite.Scalar().Pick(rand) // create a private key x
	X := suite.Point().Mul(x, nil) // corresponding public key X

	// Generate the signature
	M := []byte("Hello World!") // message we want to sign
	sig := SchnorrSign(suite, rand, M, x)
	fmt.Print("Signature:\n" + hex.Dump(sig))

	// Verify the signature against the correct message
	err := SchnorrVerify(suite, M, X, sig)
	if err != nil {
		panic(err.Error())
	}
	fmt.Println("Signature verified against correct message.")

	// Output:
	// Signature:
	// 00000000  67 3f 25 fe d1 51 5d 1e  64 3a f7 79 2f 55 53 7c  |g?%..Q].d:.y/US||
	// 00000010  f6 8a 5a 73 d5 c7 db f4  07 58 37 cc 1c b8 bf 02  |..Zs.....X7.....|
	// 00000020  5f 0b a0 ef 0e 3e 9d 2e  08 10 69 b9 82 5f 65 b3  |_....>....i.._e.|
	// 00000030  51 f8 b8 59 9b 72 d1 d0  12 f0 c6 ac 00 2a 09 0f  |Q..Y.r.......*..|
	// Signature verified against correct message.
}
