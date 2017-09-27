package crypto

import (
	"gopkg.in/dedis/crypto.v0/abstract"
	"gopkg.in/dedis/crypto.v0/sign"
)

// SchnorrSig is a signature created using the Schnorr Signature scheme.
type SchnorrSig []byte

// SignSchnorr creates a Schnorr signature from a msg and a private key
func SignSchnorr(suite abstract.Suite, private abstract.Scalar, msg []byte) (SchnorrSig, error) {
	return sign.Schnorr(suite, private, msg)
}

// VerifySchnorr verifies a given Schnorr signature. It returns nil iff the given signature is valid.
func VerifySchnorr(suite abstract.Suite, public abstract.Point, msg []byte, sig SchnorrSig) error {
	return sign.VerifySchnorr(suite, public, msg, sig)
}
