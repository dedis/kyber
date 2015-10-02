// Package group contains generic facilities for implementing
// cryptographic groups.
package group

import (
	"crypto/cipher"
	"golang.org/x/net/context"
	"io"
)

// Marshal provides a generic implementation of Element.Marshal
// based on Element.MarshalBinary.
func Marshal(c context.Context, e Element, w io.Writer) (int, error) {
	buf, err := e.MarshalBinary()
	if err != nil {
		return 0, err
	}
	return w.Write(buf)
}

// Unmarshal provides a generic implementation of Element.Unmarshal,
// based on Element.UnmarshalBinary,
// except uses Element.Pick if r is a Cipher or cipher.Stream.
// The returned byte-count is valid only when decoding from a normal Reader,
// not when picking from a pseudorandom source.
func Unmarshal(c context.Context, e Element, r io.Reader) (int, error) {
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
