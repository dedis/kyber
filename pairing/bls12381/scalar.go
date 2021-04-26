package bls12381

import (
	"math/big"

	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/kyber/v3/group/mod"
)

var curveOrder, _ = new(big.Int).SetString("73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001", 16)

// NewKyberScalar returns a new scalar value
func NewKyberScalar() kyber.Scalar {
	return mod.NewInt64(0, curveOrder)
}
