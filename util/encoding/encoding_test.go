package encoding_test

import (
	"bytes"
	"testing"

	"github.com/dedis/kyber/suites"
	"github.com/dedis/kyber/util/encoding"
	"github.com/stretchr/testify/require"
)

var s = suites.MustFind("Ed25519")

func ErrFatal(err error) {
	if err == nil {
		return
	}
	panic(err)
}

func TestPubHexStream(t *testing.T) {
	b := &bytes.Buffer{}
	p := s.Point().Pick(s.RandomStream())
	ErrFatal(encoding.WriteHexPoint(s, b, p))
	ErrFatal(encoding.WriteHexPoint(s, b, p))
	p2, err := encoding.ReadHexPoint(s, b)
	ErrFatal(err)
	require.Equal(t, p.String(), p2.String())
	p2, err = encoding.ReadHexPoint(s, b)
	ErrFatal(err)
	require.Equal(t, p.String(), p2.String())
}

func TestScalarHexStream(t *testing.T) {
	b := &bytes.Buffer{}
	sc := s.Scalar().Pick(s.RandomStream())
	ErrFatal(encoding.WriteHexScalar(s, b, sc))
	ErrFatal(encoding.WriteHexScalar(s, b, sc))
	s2, err := encoding.ReadHexScalar(s, b)
	ErrFatal(err)
	require.True(t, sc.Equal(s2))
	s2, err = encoding.ReadHexScalar(s, b)
	ErrFatal(err)
	require.True(t, sc.Equal(s2))
}

func TestPubHexString(t *testing.T) {
	p := s.Point().Pick(s.RandomStream())
	pstr, err := encoding.PointToStringHex(s, p)
	ErrFatal(err)
	p2, err := encoding.StringHexToPoint(s, pstr)
	ErrFatal(err)
	require.Equal(t, p.String(), p2.String())
}

func TestScalarHexString(t *testing.T) {
	sc := s.Scalar().Pick(s.RandomStream())
	scstr, err := encoding.ScalarToStringHex(s, sc)
	ErrFatal(err)
	s2, err := encoding.StringHexToScalar(s, scstr)
	ErrFatal(err)
	require.True(t, sc.Equal(s2))
}
