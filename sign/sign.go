package sign

import (
	"crypto/cipher"

	"go.dedis.ch/kyber/v4"
	"go.dedis.ch/kyber/v4/share"
)

// Scheme is the minimal interface for a signature scheme.
// Implemented by BLS and TBLS
type Scheme interface {
	NewKeyPair(random cipher.Stream) (kyber.Scalar, kyber.Point)
	Sign(private kyber.Scalar, msg []byte) ([]byte, error)
	Verify(public kyber.Point, msg, sig []byte) error
}

// AggregatableScheme is an interface allowing to aggregate signatures and
// public keys to efficient verification.
type AggregatableScheme interface {
	Scheme
	AggregateSignatures(sigs ...[]byte) ([]byte, error)
	AggregatePublicKeys(Xs ...kyber.Point) kyber.Point
}

// ThresholdScheme is a threshold signature scheme that issues partial
// signatures and can recover a "full" signature. It is implemented by the tbls
// package.
// TODO: see any potential conflict or synergy with mask and policy
type ThresholdScheme interface {
	Sign(private *share.PriShare, msg []byte) ([]byte, error)
	IndexOf(signature []byte) (int, error)
	Recover(public *share.PubPoly, msg []byte, sigs [][]byte, t, n uint32) ([]byte, error)
	VerifyPartial(public *share.PubPoly, msg, sig []byte) error
	VerifyRecovered(public kyber.Point, msg, sig []byte) error
}
