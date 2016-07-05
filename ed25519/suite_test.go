package ed25519

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

var edSuite = NewAES128SHA256Ed25519(false)

func TestCurvePointClone(t *testing.T) {
	P1, _ := edSuite.Point().Pick(nil, edSuite.Cipher(nil))
	P2 := P1.Clone()
	assert.True(t, P1.Equal(P2))
}

func TestCurvePointCloneRandom(t *testing.T) {
	if testing.Short() {
		t.Skip("Randomized test skipped in short mode")
	}
	iters := 1000
	null := edSuite.Point().Null()
	for iters > 0 {
		P1, _ := edSuite.Point().Pick(nil, edSuite.Cipher(nil))
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
	P1, _ := edSuite.Point().Pick([]byte("one_point"), edSuite.Cipher(nil))
	P2 := edSuite.Point()
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
	null := edSuite.Point().Null()
	for iters > 0 {

		P1, _ := edSuite.Point().Pick(nil, edSuite.Cipher(nil))
		P2 := edSuite.Point()
		P2.Set(P1)
		assert.True(t, P1.Equal(P2))
		if !P1.Equal(null) {
			P1.Add(P1, P1)
			assert.False(t, P1.Equal(P2))
		}
		iters--
	}
}
