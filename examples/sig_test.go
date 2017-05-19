package examples

import (
	"bytes"
	"crypto/cipher"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/dedis/kyber"
	"github.com/dedis/kyber/group/nist"
)

type Suite interface {
	kyber.Group
	Cipher(key []byte, options ...interface{}) kyber.Cipher
	kyber.Encoding
}

// A basic, verifiable signature
type basicSig struct {
	C kyber.Scalar // challenge
	R kyber.Scalar // response
}

// Returns a secret that depends on on a message and a point
func hashSchnorr(suite Suite, message []byte, p kyber.Point) kyber.Scalar {
	pb, _ := p.MarshalBinary()
	c := group.Cipher(pb)
	c.Message(nil, nil, message)
	return group.Scalar().Pick(c)
}

// This simplified implementation of Schnorr Signatures is based on
// crypto/anon/sig.go
// The ring structure is removed and
// The anonimity set is reduced to one public key = no anonimity
func SchnorrSign(suite Suite, random cipher.Stream, message []byte,
	privateKey kyber.Scalar) []byte {

	// Create random secret v and public point commitment T
	v := group.Scalar().Pick(random)
	T := group.Point().Mul(nil, v)

	// Create challenge c based on message and T
	c := hashSchnorr(group, message, T)

	// Compute response r = v - x*c
	r := group.Scalar()
	r.Mul(privateKey, c).Sub(v, r)

	// Return verifiable signature {c, r}
	// Verifier will be able to compute v = r + x*c
	// And check that hashElgamal for T and the message == c
	buf := bytes.Buffer{}
	sig := basicSig{c, r}
	group.Write(&buf, &sig)
	return buf.Bytes()
}

func SchnorrVerify(suite Suite, message []byte, publicKey kyber.Point,
	signatureBuffer []byte) error {

	// Decode the signature
	buf := bytes.NewBuffer(signatureBuffer)
	sig := basicSig{}
	if err := group.Read(buf, &sig); err != nil {
		return err
	}
	r := sig.R
	c := sig.C

	// Compute base**(r + x*c) == T
	var P, T kyber.Point
	P = suite.Point()
	T = suite.Point()
	T.Add(T.Mul(nil, r), P.Mul(publicKey, c))

	// Verify that the hash based on the message and T
	// matches the challange c from the signature
	c = hashSchnorr(group, message, T)
	if !c.Equal(sig.C) {
		return errors.New("invalid signature")
	}

	return nil
}

// Example of using Schnorr
func ExampleSchnorr() {
	// Crypto setup
	group := nist.NewAES128SHA256P256()
	rand := group.Cipher([]byte("example"))

	// Create a public/private keypair (X,x)
	x := group.Scalar().Pick(rand) // create a private key x
	X := group.Point().Mul(nil, x) // corresponding public key X

	// Generate the signature
	M := []byte("Hello World!") // message we want to sign
	sig := SchnorrSign(group, rand, M, x)
	fmt.Print("Signature:\n" + hex.Dump(sig))

	// Verify the signature against the correct message
	err := SchnorrVerify(group, M, X, sig)
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
