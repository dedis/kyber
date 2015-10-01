// Package group contains generic facilities for implementing
// cryptographic groups.
package group

import (
	"crypto/cipher"
	"io"
)

// MarshalTo provides a generic implementation of Element.MarshalTo
// based on Element.MarshalBinary.
func MarshalTo(e Element, w io.Writer) (int, error) {
	buf, err := e.MarshalBinary()
	if err != nil {
		return 0, err
	}
	return w.Write(buf)
}

// UnmarshalFrom provides a generic implementation of Element.UnmarshalFrom,
// based on Element.UnmarshalBinary,
// except uses Element.Pick if r is a Cipher or cipher.Stream.
// The returned byte-count is valid only when decoding from a normal Reader,
// not when picking from a pseudorandom source.
func UnmarshalFrom(e Element, r io.Reader) (int, error) {
	if strm, ok := r.(cipher.Stream); ok {
		e.Pick(nil, strm)
		return -1, nil // no byte-count when picking randomly
	}
	buf := make([]byte, e.MarshalSize())
	n, err := io.ReadFull(r, buf)
	if err != nil {
		return n, err
	}
	return n, e.UnmarshalBinary(buf)
}
