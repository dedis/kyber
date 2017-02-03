package pvss

import (
	"testing"

	"github.com/dedis/crypto/abstract"
	"github.com/dedis/crypto/edwards"
	"github.com/dedis/crypto/random"
	"github.com/dedis/crypto/share"
)

func TestPVSS(test *testing.T) {

	suite := edwards.NewAES128SHA256Ed25519(false)

	G := suite.Point().Base()
	H, _ := suite.Point().Pick(nil, suite.Cipher([]byte("H")))

	n := 10
	t := 2*n/3 + 1
	x := make([]abstract.Scalar, n) // trustee private keys
	X := make([]abstract.Point, n)  // trustee public keys
	for i := 0; i < n; i++ {
		x[i] = suite.Scalar().Pick(random.Stream)
		X[i] = suite.Point().Mul(nil, x[i])
	}

	// Scalar of shared secret
	secret := suite.Scalar().Pick(random.Stream)

	// (1) Share distribution (dealer)
	encShares, pubPoly, err := EncShares(suite, H, X, secret, t)
	if err != nil {
		test.Fatal(err)
	}

	// (2) Share decryption (trustees)
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
	recovered, err := RecoverSecret(suite, G, K, E, D, t, n)
	if err != nil {
		test.Fatal(err)
	}

	// Verify recovered secret
	if !(suite.Point().Mul(nil, secret).Equal(recovered)) {
		test.Fatalf("recovered incorrect shared secret")
	}
}

func TestPVSSDelete(test *testing.T) {

	suite := edwards.NewAES128SHA256Ed25519(false)

	G := suite.Point().Base()
	H, _ := suite.Point().Pick(nil, suite.Cipher([]byte("H")))

	n := 10
	t := 2*n/3 + 1
	x := make([]abstract.Scalar, n) // trustee private keys
	X := make([]abstract.Point, n)  // trustee public keys
	for i := 0; i < n; i++ {
		x[i] = suite.Scalar().Pick(random.Stream)
		X[i] = suite.Point().Mul(nil, x[i])
	}

	// Scalar of shared secret
	secret := suite.Scalar().Pick(random.Stream)

	// (1) Share distribution (dealer)
	encShares, pubPoly, err := EncShares(suite, H, X, secret, t)
	if err != nil {
		test.Fatal(err)
	}

	// Corrupt some of the encrypted shares
	encShares[0].S.V = suite.Point().Null()
	encShares[5].S.V = suite.Point().Null()

	// (2) Share decryption (trustees)
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
	recovered, err := RecoverSecret(suite, G, K, E, D, t, n)
	if err != nil {
		test.Fatal(err)
	}

	// Verify recovered secret
	if !(suite.Point().Mul(nil, secret).Equal(recovered)) {
		test.Fatalf("recovered incorrect shared secret")
	}

}

func TestPVSSDeleteFail(test *testing.T) {

	suite := edwards.NewAES128SHA256Ed25519(false)

	G := suite.Point().Base()
	H, _ := suite.Point().Pick(nil, suite.Cipher([]byte("H")))

	n := 10
	t := 2*n/3 + 1
	x := make([]abstract.Scalar, n) // trustee private keys
	X := make([]abstract.Point, n)  // trustee public keys
	for i := 0; i < n; i++ {
		x[i] = suite.Scalar().Pick(random.Stream)
		X[i] = suite.Point().Mul(nil, x[i])
	}

	// Scalar of shared secret
	secret := suite.Scalar().Pick(random.Stream)

	// (1) Share distribution (dealer)
	encShares, pubPoly, err := EncShares(suite, H, X, secret, t)
	if err != nil {
		test.Fatal(err)
	}

	// Corrupt some of the encrypted shares
	encShares[0].S.V = suite.Point().Null()
	encShares[5].S.V = suite.Point().Null()

	// (2) Share decryption (trustees)
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
	if _, err := RecoverSecret(suite, G, K, E, D, t, n); err != errorTooFewShares {
		test.Fatal("unexpected outcome:", err) // this test is supposed to fail
	}
}

func TestPVSSBatch(test *testing.T) {

	suite := edwards.NewAES128SHA256Ed25519(false)

	G := suite.Point().Base()
	H, _ := suite.Point().Pick(nil, suite.Cipher([]byte("H")))
	_ = G

	n := 5
	t := 2*n/3 + 1
	x := make([]abstract.Scalar, n) // trustee private keys
	X := make([]abstract.Point, n)  // trustee public keys
	for i := 0; i < n; i++ {
		x[i] = suite.Scalar().Pick(random.Stream)
		X[i] = suite.Point().Mul(nil, x[i])
	}

	// (1) Share distribution (multiple dealers)
	s0 := suite.Scalar().Pick(random.Stream)
	e0, p0, err := EncShares(suite, H, X, s0, t)
	if err != nil {
		test.Fatal(err)
	}

	s1 := suite.Scalar().Pick(random.Stream)
	e1, p1, err := EncShares(suite, H, X, s1, t)
	if err != nil {
		test.Fatal(err)
	}

	s2 := suite.Scalar().Pick(random.Stream)
	e2, p2, err := EncShares(suite, H, X, s2, t)
	if err != nil {
		test.Fatal(err)
	}

	p0s := make([]*share.PubPoly, n)
	p1s := make([]*share.PubPoly, n)
	p2s := make([]*share.PubPoly, n)
	for i := 0; i < n; i++ {
		p0s[i] = p0
		p1s[i] = p1
		p2s[i] = p2
	}

	// Batch verification
	X0, E0, err := VerifyEncShareBatch(suite, H, X, p0s, e0)
	if err != nil {
		test.Fatal(err)
	}

	X1, E1, err := VerifyEncShareBatch(suite, H, X, p1s, e1)
	if err != nil {
		test.Fatal(err)
	}

	X2, E2, err := VerifyEncShareBatch(suite, H, X, p2s, e2)
	if err != nil {
		test.Fatal(err)
	}

	// Reorder (some) polys, keys, and shares
	P := []*share.PubPoly{p0, p1, p2}

	Y0 := []abstract.Point{X0[0], X1[0], X2[0]}
	Y1 := []abstract.Point{X0[1], X1[1], X2[1]}
	Y2 := []abstract.Point{X0[2], X1[2], X2[2]}
	Y3 := []abstract.Point{X0[3], X1[3], X2[3]}

	Z0 := []*PubVerShare{E0[0], E1[0], E2[0]}
	Z1 := []*PubVerShare{E0[1], E1[1], E2[1]}
	Z2 := []*PubVerShare{E0[2], E1[2], E2[2]}
	Z3 := []*PubVerShare{E0[3], E1[3], E2[3]}

	// (2) Share batch decryption (trustees)
	KD0, ED0, DD0, err := DecShareBatch(suite, H, Y0, P, x[0], Z0)
	if err != nil {
		test.Fatal(err)
	}

	KD1, ED1, DD1, err := DecShareBatch(suite, H, Y1, P, x[1], Z1)
	if err != nil {
		test.Fatal(err)
	}

	KD2, ED2, DD2, err := DecShareBatch(suite, H, Y2, P, x[2], Z2)
	if err != nil {
		test.Fatal(err)
	}

	KD3, ED3, DD3, err := DecShareBatch(suite, H, Y3, P, x[3], Z3)
	if err != nil {
		test.Fatal(err)
	}

	// Re-establish order
	XF0 := []abstract.Point{KD0[0], KD1[0], KD2[0], KD3[0]}
	XF1 := []abstract.Point{KD0[1], KD1[1], KD2[1], KD3[1]}
	XF2 := []abstract.Point{KD0[2], KD1[2], KD2[2], KD3[2]}

	EF0 := []*PubVerShare{ED0[0], ED1[0], ED2[0], ED3[0]}
	EF1 := []*PubVerShare{ED0[1], ED1[1], ED2[1], ED3[1]}
	EF2 := []*PubVerShare{ED0[2], ED1[2], ED2[2], ED3[2]}

	DF0 := []*PubVerShare{DD0[0], DD1[0], DD2[0], DD3[0]}
	DF1 := []*PubVerShare{DD0[1], DD1[1], DD2[1], DD3[1]}
	DF2 := []*PubVerShare{DD0[2], DD1[2], DD2[2], DD3[2]}

	// (3) Recover secrets
	S0, err := RecoverSecret(suite, G, XF0, EF0, DF0, t, n)
	if err != nil {
		test.Fatal(err)
	}

	S1, err := RecoverSecret(suite, G, XF1, EF1, DF1, t, n)
	if err != nil {
		test.Fatal(err)
	}

	S2, err := RecoverSecret(suite, G, XF2, EF2, DF2, t, n)
	if err != nil {
		test.Fatal(err)
	}

	// Verify secrets
	if !(suite.Point().Mul(nil, s0).Equal(S0)) {
		test.Fatalf("recovered incorrect shared secret S0")
	}

	if !(suite.Point().Mul(nil, s1).Equal(S1)) {
		test.Fatalf("recovered incorrect shared secret S1")
	}

	if !(suite.Point().Mul(nil, s2).Equal(S2)) {
		test.Fatalf("recovered incorrect shared secret S2")
	}

}
