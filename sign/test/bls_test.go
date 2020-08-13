package test

import (
	"testing"

	bls "github.com/drand/kyber-bls12381"
	sign "github.com/drand/kyber/sign/bls"
)

func TestBLS12381(t *testing.T) {
	suite := bls.NewBLS12381Suite()
	scheme := sign.NewSchemeOnG1(suite)
	SchemeTesting(t, scheme)
}
