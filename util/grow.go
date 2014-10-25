package util

// Grow a slice so as to hold at least n bytes after its current length.
// If the slice already has sufficient capacity, simply extends the slice;
// otherwise allocates a larger slice and copies the existing portion.
// Returns the complete new slice, and a sub-slice representing
// the newly-allocated n-byte region, which the caller must initialize.
//
// Would be nice to have this in Go's bytes package.
func Grow(buf []byte, n int) ([]byte,[]byte) {
	l := len(buf)
	nl := l+n
	if nl > cap(buf) {
		newbuf := make([]byte, nl, (nl+1)*2)
		copy(newbuf, buf)
		buf = newbuf
	}
	return buf[:nl],buf[l:nl]
}

