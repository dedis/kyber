package pvss

import (
	"testing"

	"github.com/dedis/crypto/abstract"
	"github.com/dedis/crypto/edwards"
	"github.com/dedis/crypto/random"
	"github.com/dedis/crypto/share"
)

func TestPVSS(t *testing.T) {

	suite := edwards.NewAES128SHA256Ed25519(false)

	G := suite.Point().Base()
	H, _ := suite.Point().Pick(nil, suite.Cipher([]byte("H")))

	n := 10
	k := 2*n/3 + 1
	x := make([]abstract.Scalar, n) // trustee private keys
	X := make([]abstract.Point, n)  // trustee public keys
	for i := 0; i < n; i++ {
		x[i] = suite.Scalar().Pick(random.Stream)
		X[i] = suite.Point().Mul(nil, x[i])
	}

	// Scalar of shared secret
	secret := suite.Scalar().Pick(random.Stream)

	// (1) Share distribution (dealer)
	encShares, pubPoly, err := EncShares(suite, H, X, secret, k)
	if err != nil {
		t.Fatal(err)
	}

	// (2) Share decryption (trustee)
	polys := make([]*share.PubPoly, n)
	for i := 0; i < n; i++ {
		polys[i] = pubPoly // NOTE: polynomials can be different
	}

	var K []abstract.Point // good public keys
	var E []*PubVerShare   // good encrypted shares
	var D []*PubVerShare   // good decrypted shares

	for i := 0; i < n; i++ {
		if ds, err := DecShare(suite, H, X[i], polys[i], x[i], encShares[i]); err == nil {
			K = append(K, X[i])
			E = append(E, encShares[i])
			D = append(D, ds)
		}
	}

	// (3) Check decrypted shares and recover secret if possible (dealer/3rd party)
	recovered, err := RecoverSecret(suite, G, K, E, D, k, n)
	if err != nil {
		t.Fatal(err)
	}

	// Verify recovered secret
	if !(suite.Point().Mul(nil, secret).Equal(recovered)) {
		t.Fatalf("recovered incorrect shared secret")
	}
}

func TestPVSSDelete(t *testing.T) {

	suite := edwards.NewAES128SHA256Ed25519(false)

	G := suite.Point().Base()
	H, _ := suite.Point().Pick(nil, suite.Cipher([]byte("H")))

	n := 10
	k := 2*n/3 + 1
	x := make([]abstract.Scalar, n) // trustee private keys
	X := make([]abstract.Point, n)  // trustee public keys
	for i := 0; i < n; i++ {
		x[i] = suite.Scalar().Pick(random.Stream)
		X[i] = suite.Point().Mul(nil, x[i])
	}

	// Scalar of shared secret
	secret := suite.Scalar().Pick(random.Stream)

	// (1) Share distribution (dealer)
	encShares, pubPoly, err := EncShares(suite, H, X, secret, k)
	if err != nil {
		t.Fatal(err)
	}

	// Corrupt some of the encrypted shares
	encShares[0].S.V = suite.Point().Null()
	encShares[5].S.V = suite.Point().Null()

	// (2) Share decryption (trustee)
	polys := make([]*share.PubPoly, n)
	for i := 0; i < n; i++ {
		polys[i] = pubPoly // NOTE: polynomials can be different
	}

	var K []abstract.Point // good public keys
	var E []*PubVerShare   // good encrypted shares
	var D []*PubVerShare   // good decrypted shares

	for i := 0; i < n; i++ {
		if ds, err := DecShare(suite, H, X[i], polys[i], x[i], encShares[i]); err == nil {
			K = append(K, X[i])
			E = append(E, encShares[i])
			D = append(D, ds)
		}
	}

	// Corrupt some of the decrypted shares
	D[1].S.V = suite.Point().Null()

	// (3) Check decrypted shares and recover secret if possible (dealer/3rd party)
	recovered, err := RecoverSecret(suite, G, K, E, D, k, n)
	if err != nil {
		t.Fatal(err)
	}

	// Verify recovered secret
	if !(suite.Point().Mul(nil, secret).Equal(recovered)) {
		t.Fatalf("recovered incorrect shared secret")
	}

}

func TestPVSSDeleteFail(t *testing.T) {

	suite := edwards.NewAES128SHA256Ed25519(false)

	G := suite.Point().Base()
	H, _ := suite.Point().Pick(nil, suite.Cipher([]byte("H")))

	n := 10
	k := 2*n/3 + 1
	x := make([]abstract.Scalar, n) // trustee private keys
	X := make([]abstract.Point, n)  // trustee public keys
	for i := 0; i < n; i++ {
		x[i] = suite.Scalar().Pick(random.Stream)
		X[i] = suite.Point().Mul(nil, x[i])
	}

	// Scalar of shared secret
	secret := suite.Scalar().Pick(random.Stream)

	// (1) Share distribution (dealer)
	encShares, pubPoly, err := EncShares(suite, H, X, secret, k)
	if err != nil {
		t.Fatal(err)
	}

	// Corrupt some of the encrypted shares
	encShares[0].S.V = suite.Point().Null()
	encShares[5].S.V = suite.Point().Null()

	// (2) Share decryption (trustee)
	polys := make([]*share.PubPoly, n)
	for i := 0; i < n; i++ {
		polys[i] = pubPoly // NOTE: polynomials can be different
	}

	var K []abstract.Point // good public keys
	var E []*PubVerShare   // good encrypted shares
	var D []*PubVerShare   // good decrypted shares

	for i := 0; i < n; i++ {
		if ds, err := DecShare(suite, H, X[i], polys[i], x[i], encShares[i]); err == nil {
			K = append(K, X[i])
			E = append(E, encShares[i])
			D = append(D, ds)
		}
	}

	// Corrupt enough decrypted shares to make the secret unrecoverable
	D[0].S.V = suite.Point().Null()
	D[1].S.V = suite.Point().Null()

	// (3) Check decrypted shares and recover secret if possible (dealer/3rd party)
	if _, err := RecoverSecret(suite, G, K, E, D, k, n); err != errorTooFewShares {
		t.Fatal("unexpected test outcome:", err) // this test is supposed to fail
	}
}
