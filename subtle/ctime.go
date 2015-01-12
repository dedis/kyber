package subtle

import (
	"crypto/subtle"
)


// ConstantTimeCompare returns 1 iff the two equal length slices, x
// and y, have equal contents. The time taken is a function of the length of
// the slices and is independent of the contents.
func ConstantTimeCompare(x, y []byte) int {
	return subtle.ConstantTimeCompare(x, y)
}

// ConstantTimeNonzero returns a nonzero value
// iff any byte in buf has a nonzero value.
func ConstantTimeNonzero(buf []byte) byte {
	var or byte
	for _, b := range(buf) {
		or |= b
	}
	return or
}

