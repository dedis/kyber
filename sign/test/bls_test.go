package test

import (
	"testing"

	"go.dedis.ch/kyber/v4/internal/test"
	circl "go.dedis.ch/kyber/v4/pairing/bls12381/circl"
	sign "go.dedis.ch/kyber/v4/sign/bls"
)

func TestCirclBLS12381(t *testing.T) {
	suite := circl.NewSuiteBLS12381()
	scheme := sign.NewSchemeOnG1(suite)
	test.SchemeTesting(t, scheme)
}
