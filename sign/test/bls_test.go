package test

import (
	"testing"

<<<<<<< HEAD
	bls "go.dedis.ch/kyber/v3/pairing/bls12381/kilic"
=======
	bls "go.dedis.ch/kyber/v3/pairing/circl_bls12381"
>>>>>>> origin/drandmerge
	sign "go.dedis.ch/kyber/v3/sign/bls"
)

func TestBLS12381(t *testing.T) {
<<<<<<< HEAD
	suite := bls.NewBLS12381Suite()
=======
	suite := bls.NewSuiteBLS12381()
>>>>>>> origin/drandmerge
	scheme := sign.NewSchemeOnG1(suite)
	SchemeTesting(t, scheme)
}
