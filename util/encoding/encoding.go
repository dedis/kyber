package encoding

import (
	"crypto/cipher"
	"io"

	"github.com/dedis/crypto"
)

// PointEncodeTo provides a generic implementation of Point.EncodeTo
// based on Point.Encode.
func PointMarshalTo(p kyber.Point, w io.Writer) (int, error) {
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
func PointUnmarshalFrom(p kyber.Point, r io.Reader) (int, error) {
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

// ScalarEncodeTo provides a generic implementation of Scalar.EncodeTo
// based on Scalar.Encode.
func ScalarMarshalTo(s kyber.Scalar, w io.Writer) (int, error) {
	buf, err := s.MarshalBinary()
	if err != nil {
		return 0, err
	}
	return w.Write(buf)
}

// ScalarDecodeFrom provides a generic implementation of Scalar.DecodeFrom,
// based on Scalar.Decode, or Scalar.Pick if r is a Cipher or cipher.Stream.
// The returned byte-count is valid only when decoding from a normal Reader,
// not when picking from a pseudorandom source.
func ScalarUnmarshalFrom(s kyber.Scalar, r io.Reader) (int, error) {
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
