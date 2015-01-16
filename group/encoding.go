// Package group contains generic facilities for implementing
// cryptographic groups.
package group

import (
	"crypto/cipher"
	"github.com/dedis/crypto/abstract"
	"io"
)

// PointEncodeTo provides a generic implementation of Point.EncodeTo
// based on Point.Encode.
func PointEncodeTo(p abstract.Point, w io.Writer) (int, error) {
	return w.Write(p.Encode())
}

// PointDecodeFrom provides a generic implementation of Point.DecodeFrom,
// based on Point.Decode, or Point.Pick if r is a Cipher or cipher.Stream.
// The returned byte-count is valid only when decoding from a normal Reader,
// not when picking from a pseudorandom source.
func PointDecodeFrom(p abstract.Point, r io.Reader) (int, error) {
	if strm, ok := r.(cipher.Stream); ok {
		p.Pick(nil, strm)
		return -1, nil // no byte-count when picking randomly
	}
	buf := make([]byte, p.Len())
	n, err := io.ReadFull(r, buf)
	if err != nil {
		return n, err
	}
	return n, p.Decode(buf)
}

// SecretEncodeTo provides a generic implementation of Secret.EncodeTo
// based on Secret.Encode.
func SecretEncodeTo(s abstract.Secret, w io.Writer) (int, error) {
	return w.Write(s.Encode())
}

// SecretDecodeFrom provides a generic implementation of Secret.DecodeFrom,
// based on Secret.Decode, or Secret.Pick if r is a Cipher or cipher.Stream.
// The returned byte-count is valid only when decoding from a normal Reader,
// not when picking from a pseudorandom source.
func SecretDecodeFrom(s abstract.Secret, r io.Reader) (int, error) {
	if strm, ok := r.(cipher.Stream); ok {
		s.Pick(strm)
		return -1, nil // no byte-count when picking randomly
	}
	buf := make([]byte, s.Len())
	n, err := io.ReadFull(r, buf)
	if err != nil {
		return n, err
	}
	return n, s.Decode(buf)
}
