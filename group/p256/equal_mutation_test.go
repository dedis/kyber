//go:build !constantTime

package p256

import (
	"math/big"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestEqualDoesNotMutate verifies that Equal does not modify either operand.
// Regression test for https://github.com/dedis/kyber/issues/625
func TestEqualDoesNotMutate(t *testing.T) {
	suite := NewBlakeSHA256P256()

	a := suite.Point().Pick(suite.RandomStream()).(*curvePoint)
	b := suite.Point().Pick(suite.RandomStream())

	origX := new(big.Int).Set(a.x)

	// Make x non-normalized by adding the field modulus.
	// Mathematically equivalent (mod P), but numerically different.
	a.x.Add(a.x, a.c.p.P)
	require.NotEqual(t, 0, a.x.Cmp(origX), "sanity: x should differ after adding P")

	a.Equal(b)

	require.NotEqual(t, 0, a.x.Cmp(origX),
		"Equal() should not normalize the receiver's coordinates")
}

// TestEqualDoesNotMutateArgument verifies Equal doesn't modify the argument.
func TestEqualDoesNotMutateArgument(t *testing.T) {
	suite := NewBlakeSHA256P256()

	a := suite.Point().Pick(suite.RandomStream())
	b := suite.Point().Pick(suite.RandomStream()).(*curvePoint)

	origBX := new(big.Int).Set(b.x)
	b.x.Add(b.x, b.c.p.P)

	a.Equal(b)

	require.NotEqual(t, 0, b.x.Cmp(origBX),
		"Equal() should not normalize the argument's coordinates")
}

// TestSetDeepCopies verifies that Set copies coordinate values, not pointers.
func TestSetDeepCopies(t *testing.T) {
	suite := NewBlakeSHA256P256()

	a := suite.Point().Pick(suite.RandomStream()).(*curvePoint)
	b := suite.Point().(*curvePoint)
	b.c = a.c
	b.Set(a)

	require.NotSame(t, a.x, b.x, "Set should deep-copy x, not alias the pointer")
	require.NotSame(t, a.y, b.y, "Set should deep-copy y, not alias the pointer")
	require.True(t, a.Equal(b), "Set copy should be equal to original")
}

// TestCloneDeepCopies verifies that Clone copies coordinate values, not pointers.
func TestCloneDeepCopies(t *testing.T) {
	suite := NewBlakeSHA256P256()

	a := suite.Point().Pick(suite.RandomStream()).(*curvePoint)
	b := a.Clone().(*curvePoint)

	require.NotSame(t, a.x, b.x, "Clone should deep-copy x, not alias the pointer")
	require.NotSame(t, a.y, b.y, "Clone should deep-copy y, not alias the pointer")
	require.True(t, a.Equal(b), "Clone should be equal to original")
}

// TestBaseDeepCopies verifies that Base does not alias the curve's global
// generator coordinates.
func TestBaseDeepCopies(t *testing.T) {
	suite := NewBlakeSHA256P256()

	base := suite.Point().Base().(*curvePoint)

	require.NotSame(t, base.c.p.Gx, base.x,
		"Base should deep-copy Gx, not alias the curve parameter")
	require.NotSame(t, base.c.p.Gy, base.y,
		"Base should deep-copy Gy, not alias the curve parameter")
}
