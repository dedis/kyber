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
func PointMarshalTo(p *abstract.Point, w io.Writer) (int, error) {
	buf, err := p.MarshalBinary()
	if err != nil {
		return 0, err
	}
	return w.Write(buf)
}

// PointDecodeFrom provides a generic implementation of Point.DecodeFrom,
// based on Point.Decode, or Point.Pick if r is a Cipher or cipher.Stream.
// The returned byte-count is valid only when decoding from a normal Reader,
// not when picking from a pseudorandom source.
func PointUnmarshalFrom(p *abstract.Point, r io.Reader) (int, error) {
	if strm, ok := r.(cipher.Stream); ok {
		p.Pick(nil, strm)
		return -1, nil // no byte-count when picking randomly
	}
	buf := make([]byte, p.MarshalSize())
	n, err := io.ReadFull(r, buf)
	if err != nil {
		return n, err
	}
	return n, p.UnmarshalBinary(buf)
}

// SecretEncodeTo provides a generic implementation of Secret.EncodeTo
// based on Secret.Encode.
func SecretMarshalTo(s *abstract.Secret, w io.Writer) (int, error) {
	buf, err := s.MarshalBinary()
	if err != nil {
		return 0, err
	}
	return w.Write(buf)
}

// SecretDecodeFrom provides a generic implementation of Secret.DecodeFrom,
// based on Secret.Decode, or Secret.Pick if r is a Cipher or cipher.Stream.
// The returned byte-count is valid only when decoding from a normal Reader,
// not when picking from a pseudorandom source.
func SecretUnmarshalFrom(s *abstract.Secret, r io.Reader) (int, error) {
	if strm, ok := r.(cipher.Stream); ok {
		s.Pick(strm)
		return -1, nil // no byte-count when picking randomly
	}
	buf := make([]byte, s.MarshalSize())
	n, err := io.ReadFull(r, buf)
	if err != nil {
		return n, err
	}
	return n, s.UnmarshalBinary(buf)
}
