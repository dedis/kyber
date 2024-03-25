package test

import (
	"testing"

	bls "go.dedis.ch/kyber/v3/pairing/bls12381/kilic"
	sign "go.dedis.ch/kyber/v3/sign/bls"
)

func TestBLS12381(t *testing.T) {
	suite := bls.NewBLS12381Suite()
	scheme := sign.NewSchemeOnG1(suite)
	SchemeTesting(t, scheme)
}
