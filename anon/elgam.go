package anon

import (
	"bytes"
	"errors"
	"crypto/cipher"
	"github.com/dedis/crypto/abstract"
)

type basicSig struct {
	C0 abstract.Secret
	S  abstract.Secret
}

func signH1preElGam(suite abstract.Suite, message []byte) []byte {
	H := suite.Hash()
	H.Write(message)			
	return H.Sum(nil)
}

func signH1ElGam(suite abstract.Suite, H1pb []byte, PG abstract.Point) abstract.Secret {
	H1 := suite.Hash()
	H1.Write(H1pb)
	H1.Write(PG.Encode())

	b := H1.Sum(nil)
	s := suite.Stream(b[:suite.KeyLen()])
	return suite.Secret().Pick(s)
}


func SignElGam(suite abstract.Suite, random cipher.Stream, message []byte,
	publicKey abstract.Point , privateKey abstract.Secret) []byte {

	// generate signature
	H := signH1preElGam(suite, message)

	u := suite.Secret().Pick(random)
	UB := suite.Point().Mul(nil,u)
	
	var c0 abstract.Secret
	c0 = signH1ElGam(suite, H, UB)

	var s abstract.Secret
	s = suite.Secret()
	s.Mul(privateKey, c0).Sub(u, s)

	// sign
	buf := bytes.Buffer{}
	sig := basicSig{c0,s}
	abstract.Write(&buf, &sig, suite)

	return buf.Bytes()
}

func VerifyElGam(suite abstract.Suite, message []byte, publicKey abstract.Point, 
		    signatureBuffer []byte) error {

	// Decode the signature
	buf := bytes.NewBuffer(signatureBuffer)
	sig := basicSig{}
	if err := abstract.Read(buf, &sig, suite); err != nil {
		return err
	}

	H := signH1preElGam(suite, message)
	s := sig.S
	c0 := sig.C0

	// Verify the signature
	var P,PG abstract.Point
	P = suite.Point()
	PG = suite.Point()
	PG.Add(PG.Mul(nil,s),P.Mul(publicKey,c0))
	c0 = signH1ElGam(suite, H, PG)

	if !c0.Equal(sig.C0) {
		return errors.New("invalid signature")
	}

	return nil
}