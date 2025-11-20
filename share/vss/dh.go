package vss

import (
	"crypto/aes"
	"crypto/cipher"
	"hash"

	"go.dedis.ch/kyber/v4"
	"golang.org/x/crypto/hkdf"
)

// dhExchange computes the shared key from a private key and a public key
func DhExchange(suite Suite, ownPrivate kyber.Scalar, remotePublic kyber.Point) kyber.Point {
	sk := suite.Point()
	sk.Mul(ownPrivate, remotePublic)
	return sk
}

var sharedKeyLength = 32

// newAEAD returns the AEAD cipher to be use to encrypt a share
func NewAEAD(fn func() hash.Hash, preSharedKey kyber.Point, context []byte) (cipher.AEAD, error) {
	preBuff, _ := preSharedKey.MarshalBinary()
	reader := hkdf.New(fn, preBuff, nil, context)

	sharedKey := make([]byte, sharedKeyLength)
	if _, err := reader.Read(sharedKey); err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(sharedKey)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	return gcm, err
}

// keySize is arbitrary, make it long enough to seed the XOF
const KeySize = 128

func Context(suite Suite, dealer kyber.Point, verifiers []kyber.Point) ([]byte, error) {
	h := suite.XOF([]byte("vss-dealer"))
	_, err := dealer.MarshalTo(h)
	if err != nil {
		return nil, err
	}
	_, err = h.Write([]byte("vss-verifiers"))
	if err != nil {
		return nil, err
	}

	for _, v := range verifiers {
		_, err = v.MarshalTo(h)
		if err != nil {
			return nil, err
		}
	}

	sum := make([]byte, KeySize)
	_, err = h.Read(sum)
	return sum, err
}
