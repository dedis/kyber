//go:build !constantTime

package kilic

import (
	"go.dedis.ch/kyber/v4"
	"go.dedis.ch/kyber/v4/compatible"
	"go.dedis.ch/kyber/v4/group/mod"
)

var curveOrder, _ = new(compatible.Int).SetString("73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001", 16)

func NewScalar() kyber.Scalar {
	return mod.NewInt64(0, curveOrder)
}
