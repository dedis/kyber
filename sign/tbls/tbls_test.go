package tbls

import (
	"testing"

	"github.com/drand/kyber/pairing/bn256"
	"github.com/drand/kyber/pairing/circl_bls12381"
	"github.com/drand/kyber/sign/test"
)

func TestBN256(t *testing.T) {
	suite := bn256.NewSuite()
	scheme := NewThresholdSchemeOnG1(suite)
	test.ThresholdTest(t, suite.G2(), scheme)
}

func TestBLS12381(t *testing.T) {
	suite := circl_bls12381.NewSuite()
	scheme := NewThresholdSchemeOnG1(suite)
	test.ThresholdTest(t, suite.G2(), scheme)
}
