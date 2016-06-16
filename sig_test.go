package crypto

import (
	"bytes"
	"crypto/cipher"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/dedis/crypto/abstract"
	"github.com/dedis/crypto/nist"
)

// A basic, verifiable signature
type basicSig struct {
	C abstract.Scalar // challenge
	R abstract.Scalar // response
}

// Returns a secret that depends on on a message and a point
func hashSchnorr(suite abstract.Suite, message []byte, p abstract.Point) abstract.Scalar {
	pb, _ := p.MarshalBinary()
	c := suite.Cipher(pb)
	c.Message(nil, nil, message)
	return suite.Scalar().Pick(c)
}

// This simplified implementation of Schnorr Signatures is based on
// crypto/anon/sig.go
// The ring structure is removed and
// The anonimity set is reduced to one public key = no anonimity
func SchnorrSign(suite abstract.Suite, random cipher.Stream, message []byte,
	privateKey abstract.Scalar) []byte {

	// Create random secret v and public point commitment T
	v := suite.Scalar().Pick(random)
	T := suite.Point().Mul(nil, v)

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
	suite.Write(&buf, &sig)
	return buf.Bytes()
}

func SchnorrVerify(suite abstract.Suite, message []byte, publicKey abstract.Point,
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
	var P, T abstract.Point
	P = suite.Point()
	T = suite.Point()
	T.Add(T.Mul(nil, r), P.Mul(publicKey, c))

	// Verify that the hash based on the message and T
	// matches the challange c from the signature
	c = hashSchnorr(suite, message, T)
	if !c.Equal(sig.C) {
		return errors.New("invalid signature")
	}

	return nil
}

// Example of using Schnorr
func ExampleSchnorr() {
	// Crypto setup
	suite := nist.NewAES128SHA256P256()
	rand := suite.Cipher([]byte("example"))

	// Create a public/private keypair (X,x)
	x := suite.Scalar().Pick(rand) // create a private key x
	X := suite.Point().Mul(nil, x) // corresponding public key X

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
	// 00000000  c1 7a 91 74 06 48 5d 53  d4 92 27 71 58 07 eb d5  |.z.t.H]S..'qX...|
	// 00000010  75 a5 89 92 78 67 fc b1  eb 36 55 63 d1 32 12 20  |u...xg...6Uc.2. |
	// 00000020  2c 78 84 81 04 0d 2a a8  fa 80 d0 e8 c3 14 65 e3  |,x....*.......e.|
	// 00000030  7f f2 7c 55 c5 d2 c6 70  51 89 40 cd 63 50 bf c6  |..|U...pQ.@.cP..|
	// Signature verified against correct message.
}
