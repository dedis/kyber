package nist

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

var testSuite = NewAES128SHA256P256()

func TestCurvePointClone(t *testing.T) {
	P1, _ := testSuite.Point().Pick(nil, testSuite.Cipher(nil))
	P2 := P1.Clone()
	assert.True(t, P1.Equal(P2))
}

func TestCurvePointCloneRandom(t *testing.T) {
	if testing.Short() {
		t.Skip("Randomized test skipped in short mode")
	}
	iters := 1000
	null := testSuite.Point().Null()
	for iters > 0 {
		P1, _ := testSuite.Point().Pick(nil, testSuite.Cipher(nil))
		P2 := P1.Clone()
		assert.True(t, P1.Equal(P2))
		if !P1.Equal(null) {
			P1.Add(P1, P1)
			assert.False(t, P1.Equal(P2))
		}

		iters--
	}
}

func TestCurvePointSet(t *testing.T) {
	P1, _ := testSuite.Point().Pick([]byte("one_point"), testSuite.Cipher(nil))
	P2 := testSuite.Point()
	P2.Set(P1)
	assert.True(t, P1.Equal(P2))

	P1.Add(P1, P1)
	assert.False(t, P1.Equal(P2))
}

func TestCurvePointRandom(t *testing.T) {
	if testing.Short() {
		t.Skip("Randomized test skipped in short mode")
	}
	iters := 1000
	null := testSuite.Point().Null()
	for iters > 0 {

		P1, _ := testSuite.Point().Pick(nil, testSuite.Cipher(nil))
		P2 := testSuite.Point()
		P2.Set(P1)
		assert.True(t, P1.Equal(P2))
		if !P1.Equal(null) {
			P1.Add(P1, P1)
			assert.False(t, P1.Equal(P2))
		}
		iters--
	}
}
