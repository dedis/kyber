package test

import (
	"testing"

	"go.dedis.ch/kyber/v3/internal/test"
	circl "go.dedis.ch/kyber/v3/pairing/bls12381/circl"
	kilic "go.dedis.ch/kyber/v3/pairing/bls12381/kilic"
	sign "go.dedis.ch/kyber/v3/sign/bls"
)

func TestCirclBLS12381(t *testing.T) {
	suite := circl.NewSuiteBLS12381()
	scheme := sign.NewSchemeOnG1(suite)
	test.SchemeTesting(t, scheme)
}

func TestKilicBLS12381(t *testing.T) {
	suite := kilic.NewBLS12381Suite()
	scheme := sign.NewSchemeOnG2(suite)
	test.SchemeTesting(t, scheme)
}
