//go:build !constantTime

package test

import (
	"go.dedis.ch/kyber/v4/internal/test"
	sign "go.dedis.ch/kyber/v4/sign/bls"
	"testing"
)

func TestKilicBLS12381(t *testing.T) {
	suite := kilic.NewBLS12381Suite()
	scheme := sign.NewSchemeOnG2(suite)
	test.SchemeTesting(t, scheme)
}

func TestGnarkBLS12381G1(t *testing.T) {
	suite := gnark.NewSuiteBLS12381()
	scheme := sign.NewSchemeOnG1(suite)
	test.SchemeTesting(t, scheme)
}

func TestGnarkBLS12381G2(t *testing.T) {
	suite := gnark.NewSuiteBLS12381()
	scheme := sign.NewSchemeOnG2(suite)
	test.SchemeTesting(t, scheme)
}
