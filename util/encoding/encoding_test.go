package encoding

import (
	"bytes"
	"testing"

	"github.com/dedis/kyber/group/edwards25519"
	"github.com/stretchr/testify/require"
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
