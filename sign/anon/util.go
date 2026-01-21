package anon

import (
	"go.dedis.ch/kyber/v4"
	"go.dedis.ch/kyber/v4/util/random"
)

func BenchGenSig(suite Suite, nkeys int, benchMessage []byte, benchPub []kyber.Point, benchPri kyber.Scalar) []byte {
	return Sign(suite, benchMessage,
		benchPub[:nkeys], nil,
		0, benchPri)
}

func BenchGenKeys(g kyber.Group,
	nkeys int) ([]kyber.Point, kyber.Scalar) {
	rng := random.New()

	// Create an anonymity set of random "public keys"
	X := make([]kyber.Point, nkeys)
	for i := range X { // pick random points
		X[i] = g.Point().Pick(rng)
	}

	// Make just one of them an actual public/private keypair (X[mine],x)
	x := g.Scalar().Pick(rng)
	X[0] = g.Point().Mul(x, nil)

	return X, x
}

func BenchSign(suite Suite, pub []kyber.Point, pri kyber.Scalar,
	niter int, benchMessage []byte) {
	for range niter {
		Sign(suite, benchMessage, pub, nil, 0, pri)
	}
}

func BenchVerify(suite Suite, pub []kyber.Point,
	sig []byte, niter int, benchMessage []byte) {
	for range niter {
		tag, err := Verify(suite, benchMessage, pub, nil, sig)
		if tag == nil || err != nil {
			panic("benchVerify failed")
		}
	}
}
