package proof

import (
	"fmt"
	"testing"

	"github.com/dedis/crypto/abstract"
	"github.com/dedis/crypto/edwards"
	"github.com/dedis/crypto/random"
)

func TestDLEQProof(t *testing.T) {

	suite := edwards.NewAES128SHA256Ed25519(false)

	n := 10
	var good []int
	var bad []int

	for i := 0; i < n; i++ {

		// Create some random secrets and base points
		x := suite.Scalar().Pick(random.Stream)
		g, _ := suite.Point().Pick([]byte(fmt.Sprintf("G%d", i)), random.Stream)
		h, _ := suite.Point().Pick([]byte(fmt.Sprintf("H%d", i)), random.Stream)

		proof, xG, xH, err := NewDLEQProof(suite, g, h, x)
		if err != nil {
			t.Fatal(err)
		}

		if proof.Verify(suite, g, h, xG, xH) {
			good = append(good, i)
		} else {
			bad = append(bad, i)
		}

	}

	if len(bad) != 0 {
		t.Fatalf("some proofs are invalid: %v", bad)
	}
}

func TestDLEQProofBatch(t *testing.T) {

	suite := edwards.NewAES128SHA256Ed25519(false)

	n := 10
	x := make([]abstract.Scalar, n)
	g := make([]abstract.Point, n)
	h := make([]abstract.Point, n)

	for i := 0; i < n; i++ {
		x[i] = suite.Scalar().Pick(random.Stream)
		g[i], _ = suite.Point().Pick([]byte(fmt.Sprintf("G%d", i)), random.Stream)
		h[i], _ = suite.Point().Pick([]byte(fmt.Sprintf("H%d", i)), random.Stream)
	}

	proofs, xG, xH, err := NewDLEQProofBatch(suite, g, h, x)
	if err != nil {
		t.Fatal(err)
	}

	var good []int
	var bad []int

	for i := 0; i < n; i++ {
		if proofs[i].Verify(suite, g[i], h[i], xG[i], xH[i]) {
			good = append(good, i)
		} else {
			bad = append(bad, i)
		}
	}

	if len(bad) != 0 {
		t.Fatalf("some proofs are invalid: %v", bad)
	}
}

func TestDLEQLengths(t *testing.T) {

	suite := edwards.NewAES128SHA256Ed25519(false)

	n := 10
	x := make([]abstract.Scalar, n)
	g := make([]abstract.Point, n)
	h := make([]abstract.Point, n)

	for i := 0; i < n; i++ {
		x[i] = suite.Scalar().Pick(random.Stream)
		g[i], _ = suite.Point().Pick([]byte(fmt.Sprintf("G%d", i)), random.Stream)
		h[i], _ = suite.Point().Pick([]byte(fmt.Sprintf("H%d", i)), random.Stream)
	}

	// Remove an element to make the test fail
	x = append(x[:5], x[6:]...)

	if _, _, _, err := NewDLEQProofBatch(suite, g, h, x); err != errorDifferentLengths {
		t.Fatal("unexpected outcome:", err)
	}
}
