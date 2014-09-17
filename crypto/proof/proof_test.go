package proof

import (
	"testing"
	"encoding/hex"
	"dissent/crypto"
)

func TestRep(t *testing.T) {
	suite := crypto.NewAES128SHA256P256()
	rand := crypto.RandomStream

	x := suite.Secret().Pick(rand)
	y := suite.Secret().Pick(rand)
	B := suite.Point().Base()
	X := suite.Point().Mul(nil,x)
	Y := suite.Point().Mul(X,y)
	R := suite.Point().Add(X,Y)

	svar := []string{"x","y"}
	pvar := []string{"B","X","Y","R"}
	prf := NewProof(suite,svar,pvar)

	// Simple single-secret predicate: prove X=x*B
	log := prf.Log("X","x","B")

	// Two-secret representation: prove R=x*B+y*X
	rep := prf.Rep("R",Term{"x","B"},Term{"y","X"})

	// Make an and-predicate
	and := prf.And(log,rep)
	andx := prf.And(and)

	// Make up a couple incorrect facts
	falseLog := prf.Log("Y","x","B")
	falseRep := prf.Rep("R",Term{"x","B"},Term{"y","B"})

	falseAnd := prf.And(falseLog, falseRep)

	or1 := prf.Or(falseAnd,andx).Choose(1)
	or1x := prf.Or(or1).Choose(0)	// test trivial case

	or2a := prf.Log("B","y","X")
	or2b := prf.Log("R","x","R")
	or2 := prf.Or(or2a,or2b)
	or2x := prf.Or(or2)	// test trivial case

	pred := prf.Or(or1x,or2x).Choose(0)

	println("proving "+pred.String())
	sval := map[string]crypto.Secret{ "x":x, "y":y}
	pval := map[string]crypto.Point{ "B":B, "X":X, "Y":Y, "R":R}
	pc := newSigmaProver(suite, "TEST")
	if e := prf.Prove(pred, sval, pval, pc); e != nil {
		panic("prover: "+e.Error())
	}

	proof := pc.Proof()
	println("Proof:")
	println(hex.Dump(proof))

	vc := newSigmaVerifier(suite, "TEST", proof)
	if e := prf.Verify(pred, pval, vc); e != nil {
		panic("verify: "+e.Error())
	}
}

