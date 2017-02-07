package crypto

import (
	"encoding/base64"
	"encoding/hex"
	"io"

	"errors"

	"strings"

	"gopkg.in/dedis/crypto.v0/abstract"
)

// Read64Pub reads a public point from a base64 representation
func Read64Pub(suite abstract.Suite, r io.Reader) (abstract.Point, error) {
	public := suite.Point()
	dec := base64.NewDecoder(base64.StdEncoding, r)
	err := suite.Read(dec, &public)
	return public, err
}

// Write64Pub writes a public point to a base64 representation
func Write64Pub(suite abstract.Suite, w io.Writer, point abstract.Point) error {
	enc := base64.NewEncoder(base64.StdEncoding, w)
	return write64(suite, enc, point)
}

// Read64Scalar takes a Base64-encoded scalar and returns that scalar,
// optionally an error
func Read64Scalar(suite abstract.Suite, r io.Reader) (abstract.Scalar, error) {
	s := suite.Scalar()
	dec := base64.NewDecoder(base64.StdEncoding, r)
	err := suite.Read(dec, &s)
	return s, err
}

// Write64Scalar converts a scalar key to a Base64-string
func Write64Scalar(suite abstract.Suite, w io.Writer, scalar abstract.Scalar) error {
	enc := base64.NewEncoder(base64.StdEncoding, w)
	return write64(suite, enc, scalar)
}

// ReadHexPub reads a public point from a hex representation
func ReadHexPub(suite abstract.Suite, r io.Reader) (abstract.Point, error) {
	public := suite.Point()
	buf, err := getHex(r, public.MarshalSize())
	if err != nil {
		return nil, err
	}
	public.UnmarshalBinary(buf)
	return public, err
}

// WriteHexPub writes a public point to a hex representation
func WriteHexPub(suite abstract.Suite, w io.Writer, point abstract.Point) error {
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
func ReadHexScalar(suite abstract.Suite, r io.Reader) (abstract.Scalar, error) {
	s := suite.Scalar()
	buf, err := getHex(r, s.MarshalSize())
	if err != nil {
		return nil, err
	}
	s.UnmarshalBinary(buf)
	return s, nil
}

// WriteHexScalar converts a scalar key to a hex-string
func WriteHexScalar(suite abstract.Suite, w io.Writer, scalar abstract.Scalar) error {
	buf, err := scalar.MarshalBinary()
	if err != nil {
		return err
	}
	out := hex.EncodeToString(buf)
	_, err = w.Write([]byte(out))
	return err
}

// PubToStringHex converts a Public point to a hexadecimal representation
func PubToStringHex(suite abstract.Suite, point abstract.Point) (string, error) {
	pbuf, err := point.MarshalBinary()
	return hex.EncodeToString(pbuf), err
}

// StringHexToPub reads a hexadecimal representation of a public point and convert it to the
// right struct
func StringHexToPub(suite abstract.Suite, s string) (abstract.Point, error) {
	return ReadHexPub(suite, strings.NewReader(s))
}

// PubToString64 converts a Public point to a base64 representation
func PubToString64(suite abstract.Suite, point abstract.Point) (string, error) {
	pbuf, err := point.MarshalBinary()
	return base64.StdEncoding.EncodeToString(pbuf), err
}

// String64ToPub reads a base64 representation of a public point and converts it
// back to a point.
func String64ToPub(suite abstract.Suite, s string) (abstract.Point, error) {
	return Read64Pub(suite, strings.NewReader(s))
}

// ScalarToStringHex encodes a scalar to hexadecimal
func ScalarToStringHex(suite abstract.Suite, scalar abstract.Scalar) (string, error) {
	sbuf, err := scalar.MarshalBinary()
	return hex.EncodeToString(sbuf), err
}

// StringHexToScalar reads a scalar in hexadecimal from string
func StringHexToScalar(suite abstract.Suite, str string) (abstract.Scalar, error) {
	return ReadHexScalar(suite, strings.NewReader(str))
}

// ScalarToString64 encodes a scalar to a base64
func ScalarToString64(suite abstract.Suite, scalar abstract.Scalar) (string, error) {
	sbuf, err := scalar.MarshalBinary()
	return base64.StdEncoding.EncodeToString(sbuf), err
}

// String64ToScalar reads a scalar in base64 from a string
func String64ToScalar(suite abstract.Suite, str string) (abstract.Scalar, error) {
	return Read64Scalar(suite, strings.NewReader(str))
}

func write64(suite abstract.Suite, wc io.WriteCloser, data ...interface{}) error {
	if err := suite.Write(wc, data); err != nil {
		return err
	}
	return wc.Close()
}

func getHex(r io.Reader, len int) ([]byte, error) {
	bufHex := make([]byte, len*2)
	bufByte := make([]byte, len)
	l, err := r.Read(bufHex)
	if err != nil {
		return nil, err
	}
	if l < len {
		return nil, errors.New("didn't get enough bytes from stream")
	}
	_, err = hex.Decode(bufByte, bufHex)
	if err != nil {
		return nil, err
	}
	return bufByte, nil
}
