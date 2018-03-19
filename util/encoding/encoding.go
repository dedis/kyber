// Package encoding package provides helper functions to encode/decode a Point/Scalar in
// hexadecimal.
package encoding

import (
	"encoding/hex"
	"errors"
	"io"
	"strings"

	"gopkg.in/dedis/kyber.v2"
)

// ReadHexPoint reads a point from r in hex representation.
func ReadHexPoint(group kyber.Group, r io.Reader) (kyber.Point, error) {
	point := group.Point()
	buf, err := getHex(r, point.MarshalSize())
	if err != nil {
		return nil, err
	}
	err = point.UnmarshalBinary(buf)
	return point, err
}

// WriteHexPoint writes a point in hex representation to w.
func WriteHexPoint(group kyber.Group, w io.Writer, point kyber.Point) error {
	buf, err := point.MarshalBinary()
	if err != nil {
		return err
	}
	out := hex.EncodeToString(buf)
	_, err = w.Write([]byte(out))
	return err
}

// ReadHexScalar takes a hex-encoded scalar and returns that scalar,
// optionally an error
func ReadHexScalar(group kyber.Group, r io.Reader) (kyber.Scalar, error) {
	s := group.Scalar()
	buf, err := getHex(r, s.MarshalSize())
	if err != nil {
		return nil, err
	}
	s.UnmarshalBinary(buf)
	return s, nil
}

// WriteHexScalar converts a scalar key to a hex-string
func WriteHexScalar(group kyber.Group, w io.Writer, scalar kyber.Scalar) error {
	buf, err := scalar.MarshalBinary()
	if err != nil {
		return err
	}
	out := hex.EncodeToString(buf)
	_, err = w.Write([]byte(out))
	return err
}

// PointToStringHex converts a point to a hexadecimal representation
func PointToStringHex(group kyber.Group, point kyber.Point) (string, error) {
	pbuf, err := point.MarshalBinary()
	return hex.EncodeToString(pbuf), err
}

// StringHexToPoint reads a hexadecimal representation of a point from a string.
func StringHexToPoint(group kyber.Group, s string) (kyber.Point, error) {
	return ReadHexPoint(group, strings.NewReader(s))
}

// ScalarToStringHex encodes a scalar to hexadecimal.
func ScalarToStringHex(group kyber.Group, scalar kyber.Scalar) (string, error) {
	sbuf, err := scalar.MarshalBinary()
	return hex.EncodeToString(sbuf), err
}

// StringHexToScalar reads a scalar in hexadecimal from string
func StringHexToScalar(group kyber.Group, str string) (kyber.Scalar, error) {
	return ReadHexScalar(group, strings.NewReader(str))
}

func getHex(r io.Reader, l int) ([]byte, error) {
	bufHex := make([]byte, l*2)
	bufByte := make([]byte, l)
	n, err := r.Read(bufHex)
	if err != nil {
		return nil, err
	}
	if n < len(bufHex) {
		return nil, errors.New("didn't get enough bytes from stream")
	}
	_, err = hex.Decode(bufByte, bufHex)
	if err != nil {
		return nil, err
	}
	return bufByte, nil
}
