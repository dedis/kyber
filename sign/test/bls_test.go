package test

import (
	"testing"

	bls "go.dedis.ch/kyber/v3/pairing/circl_bls12381"
	sign "go.dedis.ch/kyber/v3/sign/bls"
)

func TestBLS12381(t *testing.T) {
	suite := bls.NewSuiteBLS12381()
	scheme := sign.NewSchemeOnG1(suite)
	SchemeTesting(t, scheme)
}
