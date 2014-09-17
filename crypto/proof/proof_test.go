package proof

import (
	"testing"
	"dissent/crypto"
)

func TestRep(t *testing.T) {
	suite := crypto.NewAES128SHA256P256()
	rand := crypto.RandomStream

	x := suite.Secret().Pick(rand)
	B := suite.Point().Base()
	X := suite.Point().Mul(nil,x)

	svar := []string{"x"}
	pvar := []string{"B","X"}
	prf := NewProof(suite,pvar,

	rep := prf.Log(1,
}

