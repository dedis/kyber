package tbls

import (
	"go.dedis.ch/kyber/v3/internal/test"
	"testing"

	"go.dedis.ch/kyber/v3/pairing/bn256"
)

func TestBN256(t *testing.T) {
	suite := bn256.NewSuite()
	scheme := NewThresholdSchemeOnG1(suite)
	test.ThresholdTest(t, suite.G2(), scheme)
}
