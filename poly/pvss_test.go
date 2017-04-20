package poly

import (
	"testing"

	"github.com/dedis/cothority/log"
	"github.com/dedis/crypto/abstract"
	"github.com/dedis/crypto/edwards"
	"github.com/dedis/crypto/random"
)

func TestProof(t *testing.T) {

	suite := edwards.NewAES128SHA256Ed25519(false)

	// 1st set of base points
	g1, _ := suite.Point().Pick([]byte("G1"), random.Stream)
	h1, _ := suite.Point().Pick([]byte("H1"), random.Stream)

	// 1st secret value
	x := suite.Scalar().Pick(random.Stream)

	// 2nd set of base points
	g2, _ := suite.Point().Pick([]byte("G2"), random.Stream)
	h2, _ := suite.Point().Pick([]byte("H2"), random.Stream)

	// 2nd secret value
	y := suite.Scalar().Pick(random.Stream)

	// Create proofs
	g := []abstract.Point{g1, g2}
	h := []abstract.Point{h1, h2}
	p, err := NewDLEProof(suite, g, h, nil)
	if err != nil {
		log.ErrFatal(err)
	}

	xG, xH, core, err := p.Setup(x, y)
	if err != nil {
		log.ErrFatal(err)
	}

	// Verify proofs
	q, err := NewDLEProof(suite, g, h, core)
	if err != nil {
		log.ErrFatal(err)
	}

	_, bad, err := q.Verify(xG, xH)
	if err != nil {
		log.ErrFatal(err)
	}

	if len(bad) != 0 {
		log.Fatalf("Some proofs failed: %v", bad)
	}

}

func TestProofCollective(t *testing.T) {

	suite := edwards.NewAES128SHA256Ed25519(false)

	// 1st set of base points
	g1, _ := suite.Point().Pick([]byte("G1"), random.Stream)
	h1, _ := suite.Point().Pick([]byte("H1"), random.Stream)

	// 1st secret value
	x := suite.Scalar().Pick(random.Stream)

	// 2nd set of base points
	g2, _ := suite.Point().Pick([]byte("G2"), random.Stream)
	h2, _ := suite.Point().Pick([]byte("H2"), random.Stream)

	// 2nd secret value
	y := suite.Scalar().Pick(random.Stream)

	// Create proof
	g := []abstract.Point{g1, g2}
	h := []abstract.Point{h1, h2}
	p, err := NewDLEProof(suite, g, h, nil)
	if err != nil {
		log.ErrFatal(err)
	}

	xG, xH, core, err := p.SetupCollective(x, y)
	if err != nil {
		log.ErrFatal(err)
	}

	// Verify proof
	q, err := NewDLEProof(suite, g, h, core)
	if err != nil {
		log.ErrFatal(err)
	}

	_, bad, err := q.Verify(xG, xH)
	if err != nil {
		log.ErrFatal(err)
	}

	if len(bad) != 0 {
		log.Fatalf("Some proofs failed: %v", bad)
	}

}

func TestPVSS(t *testing.T) {

	suite := edwards.NewAES128SHA256Ed25519(false)

	G := suite.Point().Base()
	H, _ := suite.Point().Pick(nil, suite.Cipher([]byte("H")))

	n := 10
	threshold := 2*n/3 + 1
	x := make([]abstract.Scalar, n) // trustee private keys
	X := make([]abstract.Point, n)  // trustee public keys
	index := make([]int, n)
	for i := 0; i < n; i++ {
		x[i] = suite.Scalar().Pick(random.Stream)
		X[i] = suite.Point().Mul(nil, x[i])
		index[i] = i
	}

	// Scalar of shared secret
	secret := suite.Scalar().Pick(random.Stream)

	// (1) Share-Distribution (Dealer)
	pvss := NewPVSS(suite, H, threshold)
	idx, sX, encProof, pb, err := pvss.Split(X, secret)
	if err != nil {
		log.ErrFatal(err)
	}

	// (2) Share-Decryption (Trustee)
	pbx := make([][]byte, n)
	for i := 0; i < n; i++ {
		pbx[i] = pb // NOTE: polynomials can be different
	}
	sH, err := pvss.Commits(pbx, index)
	if err != nil {
		log.ErrFatal(err)
	}

	// Check that log_H(sH) == log_X(sX) using encProof
	_, bad, err := pvss.Verify(H, X, sH, sX, encProof)
	if err != nil {
		log.ErrFatal(err)

	}

	if len(bad) != 0 {
		log.Fatalf("Some proofs failed: %v", bad)
	}

	// Decrypt shares
	S := make([]abstract.Point, n)
	decProof := make([]DLEProofCore, n)
	for i := 0; i < n; i++ {
		s, d, err := pvss.Reveal(x[i], sX[i:i+1])
		if err != nil {
			log.ErrFatal(err)
		}
		S[i] = s[0]
		decProof[i] = d[0]
	}

	// Check that log_G(S) == log_X(sX) using decProof
	_, bad, err = pvss.Verify(G, S, X, sX, decProof)
	if err != nil {
		log.ErrFatal(err)
	}

	if len(bad) != 0 {
		log.Fatalf("Some proofs failed: %v", bad)
	}

	// (3) Secret-Recovery (Dealer)
	recovered, err := pvss.Recover(idx, S, len(S))
	if err != nil {
		log.ErrFatal(err)
	}

	// Verify recovered secret
	if !(suite.Point().Mul(nil, secret).Equal(recovered)) {
		log.Fatalf("Recovered incorrect shared secret")
	}
}
