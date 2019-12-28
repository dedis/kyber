package sign

import (
	"crypto/cipher"

	"go.dedis.ch/kyber/v3"
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
