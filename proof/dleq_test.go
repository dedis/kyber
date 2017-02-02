package proof_test

import (
	"testing"

	"github.com/dedis/crypto/abstract"
	"github.com/dedis/crypto/edwards"
	"github.com/dedis/crypto/proof"
	"github.com/dedis/crypto/random"
)

func TestDLEQ(t *testing.T) {

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
	p, err := proof.NewDLEQ(suite, g, h, nil)
	if err != nil {
		t.Fatal(err)
	}

	xG, xH, err := p.Setup(x, y)
	if err != nil {
		t.Fatal(err)
	}

	// Verify proofs
	q, err := proof.NewDLEQ(suite, g, h, p.Core)
	if err != nil {
		t.Fatal(err)
	}

	_, bad, err := q.Verify(xG, xH)
	if err != nil {
		t.Fatal(err)
	}

	if len(bad) != 0 {
		t.Fatalf("Some proofs failed: %v", bad)
	}

}

func TestDLEQCollective(t *testing.T) {

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
	p, err := proof.NewDLEQ(suite, g, h, nil)
	if err != nil {
		t.Fatal(err)
	}

	xG, xH, err := p.SetupCollective(x, y)
	if err != nil {
		t.Fatal(err)
	}

	// Verify proof
	q, err := proof.NewDLEQ(suite, g, h, p.Core)
	if err != nil {
		t.Fatal(err)
	}

	_, bad, err := q.Verify(xG, xH)
	if err != nil {
		t.Fatal(err)
	}

	if len(bad) != 0 {
		t.Fatalf("Some proofs failed: %v", bad)
	}

}
