package crypto

import (
	"encoding/base64"
	"encoding/hex"
	"io"

	"bytes"

	"errors"

	"github.com/dedis/crypto/abstract"
)

// ReadPub64 a public point to a base64 representation
func ReadPub64(suite abstract.Suite, r io.Reader) (abstract.Point, error) {
	public := suite.Point()
	dec := base64.NewDecoder(base64.StdEncoding, r)
	err := suite.Read(dec, &public)
	return public, err
}

// WritePub64 writes a public point to a base64 representation
func WritePub64(suite abstract.Suite, w io.Writer, point abstract.Point) error {
	enc := base64.NewEncoder(base64.StdEncoding, w)
	return write64(suite, enc, point)
}

// Pub64 converts a public point to a base64 representation
func Pub64(suite abstract.Suite, point abstract.Point) (string, error) {
	var buff bytes.Buffer
	if err := WritePub64(suite, &buff, point); err != nil {
		return "", errors.New("Couldn't convert to base64")
	}
	return buff.String(), nil
}

func write64(suite abstract.Suite, wc io.WriteCloser, data ...interface{}) error {
	if err := suite.Write(wc, data); err != nil {
		return err
	}
	return wc.Close()
}

// WriteScalar64 converts a scalar key to a Base64-string
func WriteScalar64(suite abstract.Suite, w io.Writer, scalar abstract.Scalar) error {
	enc := base64.NewEncoder(base64.StdEncoding, w)
	return write64(suite, enc, scalar)
}

// ReadScalar64 takes a Base64-encoded scalar and returns that scalar,
// optionally an error
func ReadScalar64(suite abstract.Suite, r io.Reader) (abstract.Scalar, error) {
	s := suite.Scalar()
	dec := base64.NewDecoder(base64.StdEncoding, r)
	err := suite.Read(dec, &s)
	return s, err
}

// PubHex converts a Public point to a hexadecimal representation
func PubHex(suite abstract.Suite, point abstract.Point) (string, error) {
	pbuf, err := point.MarshalBinary()
	return hex.EncodeToString(pbuf), err
}

// ReadPubHex reads a hexadecimal representation of a public point and convert it to the
// right struct
func ReadPubHex(suite abstract.Suite, s string) (abstract.Point, error) {
	encoded, err := hex.DecodeString(s)
	if err != nil {
		return nil, err
	}
	point := suite.Point()
	err = point.UnmarshalBinary(encoded)
	return point, err
}

// ScalarHex encodes a scalar to hexadecimal
func ScalarHex(suite abstract.Suite, scalar abstract.Scalar) (string, error) {
	sbuf, err := scalar.MarshalBinary()
	return hex.EncodeToString(sbuf), err
}

// ReadScalarHex reads a scalar in hexadecimal from string
func ReadScalarHex(suite abstract.Suite, str string) (abstract.Scalar, error) {
	enc, err := hex.DecodeString(str)
	if err != nil {
		return nil, err
	}
	s := suite.Scalar()
	err = s.UnmarshalBinary(enc)
	return s, err
}
