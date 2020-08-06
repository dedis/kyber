package edwards25519

import (
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestPoint_Marshal(t *testing.T) {
	p := point{}
	require.Equal(t, "ed.point", fmt.Sprintf("%s", p.MarshalID()))
}

// TestPoint_HasSmallOrder ensures weakKeys are considered to have
// a small order
func TestPoint_HasSmallOrder(t *testing.T) {
	for _, key := range weakKeys {
		p := point{}
		err := p.UnmarshalBinary(key)
		require.Nil(t, err)
		require.True(t, p.HasSmallOrder(), fmt.Sprintf("%s should be considered to have a small order", hex.EncodeToString(key)))
	}
}

// Test_pointIsCanonical ensures that elements >= p are considered
// non canonical
func Test_pointIsCanonical(t *testing.T) {

	// buffer stores the candidate points (in little endian) that we'll test
	// against, starting with `prime`
	buffer := prime.Bytes()
	for i, j := 0, len(buffer)-1; i < j; i, j = i+1, j-1 {
		buffer[i], buffer[j] = buffer[j], buffer[i]
	}

	// Iterate over the 19*2 finite field elements
	var group = new(Curve)
	point := group.Point()
	actualNonCanonicalCount := 0
	expectedNonCanonicalCount := 24
	for i := 0; i < 19; i++ {
		buffer[0] = byte(237 + i)
		buffer[31] = byte(127)

		// Check if it's a valid point on the curve that's
		// not canonical
		err := point.UnmarshalBinary(buffer)
		if err == nil && !PointIsCanonical(buffer) {
			actualNonCanonicalCount++
		}

		// flip bit
		buffer[31] |= 128

		// Check if it's a valid point on the curve that's
		// not canonical
		err = point.UnmarshalBinary(buffer)
		if err == nil && !PointIsCanonical(buffer) {
			actualNonCanonicalCount++
		}
	}
	require.Equal(t, expectedNonCanonicalCount, actualNonCanonicalCount, "Incorrect number of non canonical points detected")
}
