package anon

import (
	"bytes"
	"errors"
	"crypto/cipher"
	"github.com/dedis/crypto/abstract"
)

// Signature generation as described below:
// http://en.wikipedia.org/wiki/ElGamal_signature_scheme

type basicSig struct {
	C0 abstract.Secret
	S  abstract.Secret
}

// returns H(m)
func hash(suite abstract.Suite, message []byte) []byte {
	H := suite.Hash()
	H.Write(message)			
	return H.Sum(nil)
}

func SignElGam(suite abstract.Suite, random cipher.Stream, message []byte,
	publicKey abstract.Point , privateKey abstract.Secret) []byte {

	// generate signature
	var r abstract.Point
	var s abstract.Secret
	for {
		H := hash(suite, message)
		k := suite.Secret().Pick(random)	
		r = suite.Point().Mul(nil,k)

		var modInv abstract.Secret
		modInv.Inv(k)
		s.Mul(privateKey, r).Sub(H, s).Mul(s, modInv)  // s = (H(m) - xr)k**(-1)
		
		if ! s.Equal(0) {
			break
		}
	}

	// sign
	buf := bytes.Buffer{}
	sig := basicSig{r,s}
	abstract.Write(&buf, &sig, suite)

	return buf.Bytes()
}

func Verify(suite abstract.Suite, message []byte, publicKey abstract.Point, 
		    signatureBuffer []byte) error {


	// Decode the signature
	buf := bytes.NewBuffer(signatureBuffer)
	sig := basicSig{}
	if err := abstract.Read(buf, &sig, suite); err != nil {
		return err
	}

	var P1,P2,left abstract.Point
	P1.Mul(publicKey, sig.C0)  // y**r
	P2.Mul(sig.C0, sig.S)      // r**s
	left.Mul(nil, H)           // g**H

	var right abstract.Secret
	right.Mul(P1,P2)           // y**r * r**s

	if ! right.Equal(left) {
		return nil,errors.New("invalid signature")
	}

	return nil
}