package share

import (
	"testing"

	"github.com/dedis/crypto/abstract"
	"github.com/dedis/crypto/edwards"
	"github.com/dedis/crypto/random"
)

func TestPVSS(t *testing.T) {

	suite := edwards.NewAES128SHA256Ed25519(false)

	G := suite.Point().Base()
	H, _ := suite.Point().Pick(nil, suite.Cipher([]byte("H")))

	n := 10
	threshold := 2*n/3 + 1
	x := make([]abstract.Scalar, n) // trustee private keys
	X := make([]abstract.Point, n)  // trustee public keys
	for i := 0; i < n; i++ {
		x[i] = suite.Scalar().Pick(random.Stream)
		X[i] = suite.Point().Mul(nil, x[i])
	}

	// Scalar of shared secret
	secret := suite.Scalar().Pick(random.Stream)

	// (1) Share distribution (Dealer)
	pvss := NewPVSS(suite, H, threshold, n)
	encShares, pubPoly, err := pvss.EncShares(X, secret)
	if err != nil {
		t.Fatal(err)
	}

	// (2) Share decryption (Trustee)
	polys := make([]*PubPoly, n)
	for i := 0; i < n; i++ {
		polys[i] = pubPoly // NOTE: polynomials can be different
	}

	var ES []*PubVerShare // good encrypted shares
	var DS []*PubVerShare // good decrypted shares
	for i := 0; i < n; i++ {
		_, es, ds, err := pvss.DecShares(H, X[i:i+1], polys[i:i+1], x[i], encShares[i:i+1])
		if err != nil {
			t.Fatal(err)
		}
		ES = append(ES, es[0])
		DS = append(DS, ds[0])
	}

	// (3) Check decrypted shares and recover secret if possible (Dealer)
	recovered, err := pvss.RecoverSecret(G, X, ES, DS)
	if err != nil {
		t.Fatal(err)
	}

	// Verify recovered secret
	if !(suite.Point().Mul(nil, secret).Equal(recovered)) {
		t.Fatalf("Recovered incorrect shared secret")
	}
}

func TestPVSSDelete(t *testing.T) {

	suite := edwards.NewAES128SHA256Ed25519(false)

	G := suite.Point().Base()
	H, _ := suite.Point().Pick(nil, suite.Cipher([]byte("H")))

	n := 10
	threshold := 2*n/3 + 1
	x := make([]abstract.Scalar, n) // trustee private keys
	X := make([]abstract.Point, n)  // trustee public keys
	for i := 0; i < n; i++ {
		x[i] = suite.Scalar().Pick(random.Stream)
		X[i] = suite.Point().Mul(nil, x[i])
	}

	// Scalar of shared secret
	secret := suite.Scalar().Pick(random.Stream)

	// (1) Share distribution (Dealer)
	pvss := NewPVSS(suite, H, threshold, n)
	encShares, pubPoly, err := pvss.EncShares(X, secret)
	if err != nil {
		t.Fatal(err)
	}

	// Corrupt some of the encrypted shares
	encShares[0].S.V = suite.Point().Null()
	encShares[5].S.V = suite.Point().Null()

	// (2) Share decryption (Trustee)
	polys := make([]*PubPoly, n)
	for i := 0; i < n; i++ {
		polys[i] = pubPoly // NOTE: polynomials can be different
	}

	var XX []abstract.Point // good keys
	var ES []*PubVerShare   // good encrypted shares
	var DS []*PubVerShare   // good decrypted shares
	for i := 0; i < len(encShares); i++ {
		ks, es, ds, err := pvss.DecShares(H, X[i:i+1], polys[i:i+1], x[i], encShares[i:i+1])
		if err != nil {
			t.Fatal(err)
		}
		if len(ks) == 1 && len(es) == 1 && len(ds) == 1 {
			XX = append(XX, ks[0])
			ES = append(ES, es[0])
			DS = append(DS, ds[0])
		}
	}

	// Corrupt some of the decrypted shares
	DS[1].S.V = suite.Point().Null()

	// (3) Check decrypted shares and recover secret if possible (Dealer)
	recovered, err := pvss.RecoverSecret(G, XX, ES, DS)
	if err != nil {
		t.Fatal(err)
	}

	// Verify recovered secret
	if !(suite.Point().Mul(nil, secret).Equal(recovered)) {
		t.Fatalf("Recovered incorrect shared secret")
	}
}

func TestPVSSDeleteFail(t *testing.T) {

	suite := edwards.NewAES128SHA256Ed25519(false)

	G := suite.Point().Base()
	H, _ := suite.Point().Pick(nil, suite.Cipher([]byte("H")))

	n := 10
	threshold := 2*n/3 + 1
	x := make([]abstract.Scalar, n) // trustee private keys
	X := make([]abstract.Point, n)  // trustee public keys
	for i := 0; i < n; i++ {
		x[i] = suite.Scalar().Pick(random.Stream)
		X[i] = suite.Point().Mul(nil, x[i])
	}

	// Scalar of shared secret
	secret := suite.Scalar().Pick(random.Stream)

	// (1) Share distribution (Dealer)
	pvss := NewPVSS(suite, H, threshold, n)
	encShares, pubPoly, err := pvss.EncShares(X, secret)
	if err != nil {
		t.Fatal(err)
	}

	// Corrupt some of the encrypted shares
	encShares[0].S.V = suite.Point().Null()
	encShares[5].S.V = suite.Point().Null()

	// (2) Share decryption (Trustee)
	polys := make([]*PubPoly, n)
	for i := 0; i < n; i++ {
		polys[i] = pubPoly // NOTE: polynomials can be different
	}

	var XX []abstract.Point // good keys
	var ES []*PubVerShare   // good encrypted shares
	var DS []*PubVerShare   // good decrypted shares
	for i := 0; i < len(encShares); i++ {
		ks, es, ds, err := pvss.DecShares(H, X[i:i+1], polys[i:i+1], x[i], encShares[i:i+1])
		if err != nil {
			t.Fatal(err)
		}
		if len(ks) == 1 && len(es) == 1 && len(ds) == 1 {
			XX = append(XX, ks[0])
			ES = append(ES, es[0])
			DS = append(DS, ds[0])
		}
	}

	// Corrupt enough decrypted shares to make the secret unrecoverable
	DS[0].S.V = suite.Point().Null()
	DS[1].S.V = suite.Point().Null()

	// (3) Check decrypted shares and recover secret if possible (Dealer)
	_, err = pvss.RecoverSecret(G, XX, ES, DS)
	if err != errorTooFewShares {
		t.Fatal(err)
	}

}
