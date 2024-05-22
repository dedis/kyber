package bn254

import (
	"testing"

	"go.dedis.ch/kyber/v3/internal/test"
	"go.dedis.ch/kyber/v3/sign/bls"
)

func TestBLSSchemeBN254G1(t *testing.T) {
	suite := NewSuite()
	s := bls.NewSchemeOnG1(suite)
	test.SchemeTesting(t, s)
}
