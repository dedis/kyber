package edwards25519

import (
	"encoding/hex"
	"testing"
)

func testOneNonCanonicalGE(t *testing.T, s []byte) bool {
	if Ge25519IsCanonical(s) != 0 {
		t.Fatal(hex.Dump(s), " must be non-canonical!")
	}

	return true
}

// TestGe25519IsCanonical loops over non-canonical points
func TestGe25519IsCanonical(t *testing.T) {

	// First finite field element that can be represented non-canonically,
	//  with the size of x+p not bigger than 255 bits
	var iterFENonCanonical []byte = []byte{237, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
		255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 127}
	var ge extendedGroupElement
	var c = 0
	// Total number of non-canonical point encodings that are going to be detected with this test
	var shouldDetectNoNonCanonicalPE = 24

	// Iterate over the 19 finite field elements
	for i := 0; i < 19; i++ {
		iterFENonCanonical[0] = byte(237 + i)
		iterFENonCanonical[31] = byte(127)
		//Some field elements aren't valid curve points, detect using FromBytes
		if ge.FromBytes(iterFENonCanonical) {
			if testOneNonCanonicalGE(t, iterFENonCanonical) {
				// Increment counter only if the valid field element is non-canonical
				c++
			}
		}
		// flip bit
		iterFENonCanonical[31] |= 128
		//Some field elements aren't valid curve points, detect using FromBytes
		if ge.FromBytes(iterFENonCanonical) {
			if testOneNonCanonicalGE(t, iterFENonCanonical) {
				// Increment counter only if the valid field element is non-canonical
				c++
			}
		}
	}

	// Check that all non-canonical points have been detected
	if c != shouldDetectNoNonCanonicalPE {
		t.Fatal(c, "non-canonical points have been detected, however", shouldDetectNoNonCanonicalPE, "should have been detected!")
	}
}

// TestGe25519HasSmallOrder loops over the blocklist
func TestGe25519HasSmallOrder(t *testing.T) {

	var tmp = []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}

	for _, i := range blocklist {
		for j, elem := range i {
			tmp[j] = byte(elem)
		}

		if Ge25519HasSmallOrder(tmp) == 0 {
			t.Fatal(hex.Dump(tmp), "should have small order!")
		}
	}
}
