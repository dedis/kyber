package crypto

import (
	"encoding/base64"
	"encoding/hex"
	"io"

	"gopkg.in/dedis/crypto.v0/abstract"
)

// Read64Pub a public point to a base64 representation
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

// Write64Scalar converts a scalar key to a Base64-string
func Write64Scalar(suite abstract.Suite, w io.Writer, scalar abstract.Scalar) error {
	enc := base64.NewEncoder(base64.StdEncoding, w)
	return write64(suite, enc, scalar)
}

// Read64Scalar takes a Base64-encoded scalar and returns that scalar,
// optionally an error
func Read64Scalar(suite abstract.Suite, r io.Reader) (abstract.Scalar, error) {
	s := suite.Scalar()
	dec := base64.NewDecoder(base64.StdEncoding, r)
	err := suite.Read(dec, &s)
	return s, err
}

// PubToStringHex converts a Public point to a hexadecimal representation
func PubToStringHex(suite abstract.Suite, point abstract.Point) (string, error) {
	pbuf, err := point.MarshalBinary()
	return hex.EncodeToString(pbuf), err
}

// StringHexToPub reads a hexadecimal representation of a public point and convert it to the
// right struct
func StringHexToPub(suite abstract.Suite, s string) (abstract.Point, error) {
	encoded, err := hex.DecodeString(s)
	if err != nil {
		return nil, err
	}
	point := suite.Point()
	err = point.UnmarshalBinary(encoded)
	return point, err
}

// ScalarToStringHex encodes a scalar to hexadecimal
func ScalarToStringHex(suite abstract.Suite, scalar abstract.Scalar) (string, error) {
	sbuf, err := scalar.MarshalBinary()
	return hex.EncodeToString(sbuf), err
}

// StringHexToScalar reads a scalar in hexadecimal from string
func StringHexToScalar(suite abstract.Suite, str string) (abstract.Scalar, error) {
	enc, err := hex.DecodeString(str)
	if err != nil {
		return nil, err
	}
	s := suite.Scalar()
	err = s.UnmarshalBinary(enc)
	return s, err
}

func write64(suite abstract.Suite, wc io.WriteCloser, data ...interface{}) error {
	if err := suite.Write(wc, data); err != nil {
		return err
	}
	return wc.Close()
}
