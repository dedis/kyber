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

// TestGe25519IsCanonical loops over non-canonical points
func TestGe25519IsCanonical(t *testing.T) {

	// First finite field element that can be represented non-canonically,
	//  with the size of x+p not bigger than 255 bits
	var iterFENonCanonical []byte = []byte{237, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
		255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 127}
	var ge extendedGroupElement

	// Iterate over the 19 finite field elements
	for i := 0; i < 19; i++ {
		iterFENonCanonical[0] = byte(237 + i)
		iterFENonCanonical[31] = byte(127)
		//Some field elements aren't valid curve points, detect using FromBytes
		require.True(t, ge.FromBytes(iterFENonCanonical))

		// flip bit
		iterFENonCanonical[31] |= 128
		//Some field elements aren't valid curve points, detect using FromBytes
		require.True(t, ge.FromBytes(iterFENonCanonical))
	}
}

// TestGe25519HasSmallOrder loops over the weakKeys
func TestGe25519HasSmallOrder(t *testing.T) {

	var tmp = []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}

	for _, i := range weakKeys {
		for j, elem := range i {
			tmp[j] = byte(elem)
		}

		if Ge25519HasSmallOrder(tmp) == 0 {
			t.Fatal(hex.Dump(tmp), "should have small order!")
		}
	}
}
