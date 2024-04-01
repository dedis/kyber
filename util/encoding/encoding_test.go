package encoding

import (
	"bytes"
	"io"
	"testing"

	"github.com/stretchr/testify/require"
	"go.dedis.ch/kyber/v3/group/edwards25519"
)

var s = edwards25519.NewBlakeSHA256Ed25519()

func ErrFatal(err error) {
	if err == nil {
		return
	}
	panic(err)
}

func TestPubHexStream(t *testing.T) {
	b := &bytes.Buffer{}
	p := s.Point().Pick(s.RandomStream())
	ErrFatal(WriteHexPoint(s, b, p))
	ErrFatal(WriteHexPoint(s, b, p))
	p2, err := ReadHexPoint(s, b)
	ErrFatal(err)
	require.Equal(t, p.String(), p2.String())
	p2, err = ReadHexPoint(s, b)
	ErrFatal(err)
	require.Equal(t, p.String(), p2.String())
}

func TestScalarHexStream(t *testing.T) {
	b := &bytes.Buffer{}
	sc := s.Scalar().Pick(s.RandomStream())
	ErrFatal(WriteHexScalar(s, b, sc))
	ErrFatal(WriteHexScalar(s, b, sc))
	s2, err := ReadHexScalar(s, b)
	ErrFatal(err)
	require.True(t, sc.Equal(s2))
	s2, err = ReadHexScalar(s, b)
	ErrFatal(err)
	require.True(t, sc.Equal(s2))
}

func TestPubHexString(t *testing.T) {
	p := s.Point().Pick(s.RandomStream())
	pstr, err := PointToStringHex(s, p)
	ErrFatal(err)
	p2, err := StringHexToPoint(s, pstr)
	ErrFatal(err)
	require.Equal(t, p.String(), p2.String())
}

func TestScalarHexString(t *testing.T) {
	sc := s.Scalar().Pick(s.RandomStream())
	scstr, err := ScalarToStringHex(s, sc)
	ErrFatal(err)
	s2, err := StringHexToScalar(s, scstr)
	ErrFatal(err)
	require.True(t, sc.Equal(s2))
}

// Tests for error cases
type MockFailingReader struct {
	data []byte
}
type MockEmptyReader struct {
	data []byte
}

func (m *MockFailingReader) Read(p []byte) (n int, err error) {
	return copy(p, m.data), io.EOF
}
func (m *MockEmptyReader) Read(p []byte) (n int, err error) {
	return 0, nil
}

func TestReadHexPointErrorInvalidHexEnc(t *testing.T) {
	// Test case: invalid hex encoding
	reader := bytes.NewReader([]byte("invalidhex"))
	_, err := ReadHexPoint(s, reader)
	require.Error(t, err, "Expected error when reading invalid hex encoding, but got nil")
}

func TestReadHexPointErrorReaderFails(t *testing.T) {
	// Test case: reader fails
	mockReader1 := &MockFailingReader{data: []byte("abc")}
	_, err := ReadHexPoint(s, mockReader1)
	require.Error(t, err, "Expected error when reader fails, but got nil")
}

func TestReadHexPointErrorNotEnoughBytes(t *testing.T) {
	// Test case: not enough bytes from stream
	mockReader2 := &MockEmptyReader{data: []byte("abc")}
	_, err := ReadHexPoint(s, mockReader2)
	require.Error(t, err, "Expected error when not enough bytes from stream, but got nil")
	require.EqualError(t, err, "didn't get enough bytes from stream", "Expected error message: didn't get enough bytes from stream, but got %s", err.Error())
}
