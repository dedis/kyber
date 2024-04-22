package anon

import (
	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/kyber/v3/util/random"
)

func BenchGenSig(suite Suite, nkeys int, benchMessage []byte, benchPub []kyber.Point, benchPri kyber.Scalar) []byte {
	return Sign(suite, benchMessage,
		Set(benchPub[:nkeys]), nil,
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
	for i := 0; i < niter; i++ {
		Sign(suite, benchMessage, Set(pub), nil, 0, pri)
	}
}

func BenchVerify(suite Suite, pub []kyber.Point,
	sig []byte, niter int, benchMessage []byte) {
	for i := 0; i < niter; i++ {
		tag, err := Verify(suite, benchMessage, Set(pub), nil, sig)
		if tag == nil || err != nil {
			panic("benchVerify failed")
		}
	}
}
