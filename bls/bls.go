package bls

import (
	"crypto/cipher"
	"errors"

	"github.com/dedis/kyber/abstract"
	"github.com/dedis/kyber/pbc"
)

type PairingSuite interface {
	G1() abstract.Suite
	G2() abstract.Suite
	GT() pbc.PairingGroup
}

func NewKeyPair(s PairingSuite, r cipher.Stream) (abstract.Scalar, abstract.Point) {
	sk := s.G2().Scalar().Pick(r)
	pk := s.G2().Point().Mul(nil, sk)
	return sk, pk
}

// Performs a BLS signature operation. Namely, it computes:
//
//   x * H(m) as a point on G1
//
// where x is the private key, and m the message.
func Sign(s PairingSuite, private abstract.Scalar, msg []byte) []byte {
	HM := hashed(s, msg)
	xHM := HM.Mul(HM, private)
	sig, _ := xHM.MarshalBinary()
	return sig
}

// Verify checks the signature. Namely, it checks the equivalence between
//
//  e(H(m),X) == e(H(m), G2^x) == e(H(m)^x, G2) == e(s, G2)
//
// where m is the message, X the public key from G2, s the signature and G2 the base
// point from which the public key have been generated.
func Verify(s PairingSuite, public abstract.Point, msg, sig []byte) error {
	HM := hashed(s, msg)
	left := s.GT().PointGT().Pairing(HM, public)
	sigPoint := s.G1().Point()
	if err := sigPoint.UnmarshalBinary(sig); err != nil {
		return err
	}

	g2 := s.G2().Point().Base()
	right := s.GT().PointGT().Pairing(sigPoint, g2)

	if !left.Equal(right) {
		return errors.New("bls: invalid signature")
	}
	return nil
}

func hashed(s PairingSuite, msg []byte) abstract.Point {
	hashed := s.G1().Hash().Sum(msg)
	p, _ := s.G1().Point().Pick(nil, s.G1().Cipher(hashed))
	return p
}
