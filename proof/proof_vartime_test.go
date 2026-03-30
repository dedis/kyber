//go:build !constantTime

package proof

import (
	"strconv"
	"testing"

	"go.dedis.ch/kyber/v4/group/edwards25519vartime"

	"go.dedis.ch/kyber/v4"
	"go.dedis.ch/kyber/v4/group/edwards25519"
	"go.dedis.ch/kyber/v4/group/p256"
	"go.dedis.ch/kyber/v4/xof/blake2xb"
)

func BenchmarkProof(b *testing.B) {
	rand := blake2xb.New([]byte("random"))
	predicateSize := 100
	suites := []struct {
		Suite
	}{
		{edwards25519.NewBlakeSHA256Ed25519()},
		{edwards25519vartime.NewBlakeSHA256Ed25519(false)},
		{edwards25519vartime.NewBlakeSHA256Ed25519(true)},
		{p256.NewBlakeSHA256P256()},
		{p256.NewBlakeSHA256QR512()},
	}

	for _, suite := range suites {
		P := suite.Point().Null()

		sval := map[string]kyber.Scalar{}
		pval := map[string]kyber.Point{}
		predicateBuilder := make([]string, 0)

		for i := range predicateSize {
			s := suite.Scalar().Pick(rand)
			index := strconv.Itoa(i)

			publicPoint := suite.Point().Mul(s, nil)

			sval["x"+index] = s
			predicateBuilder = append(predicateBuilder, "x"+index)
			predicateBuilder = append(predicateBuilder, "B"+index)
			pval["B"+index] = suite.Point().Base()

			P = suite.Point().Add(P, publicPoint)
		}

		pval["P"] = P

		var proof []byte
		var err error
		var pred Predicate

		b.Run(suite.String()+"/ProofBuild", func(b *testing.B) {
			for range b.N {
				pred = Rep("P", predicateBuilder...)
				// Prove P = x0*B + x1*B + ... + xN*B
				prover := pred.Prover(suite, sval, pval, nil)
				proof, err = HashProve(suite, "TEST", prover)
				if err != nil {
					b.Log(err.Error())
					b.Fail()
				}
			}
		})

		b.Run(suite.String()+"/ProofVerify", func(b *testing.B) {
			for range b.N {
				verifier := pred.Verifier(suite, pval)
				err = HashVerify(suite, "TEST", verifier, proof)
				if err != nil {
					b.Log(err.Error())
					b.Fail()
				}
			}
		})
	}
}
