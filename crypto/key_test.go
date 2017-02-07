package crypto

import (
	"testing"

	"bytes"

	"github.com/dedis/onet/log"
	"github.com/stretchr/testify/require"
	"gopkg.in/dedis/crypto.v0/edwards"
)

var s = edwards.NewAES128SHA256Ed25519(false)

func TestMain(m *testing.M) {
	log.MainTest(m)
}

func TestPub64(t *testing.T) {
	b := &bytes.Buffer{}
	rand := s.Cipher([]byte("example"))
	p, _ := s.Point().Pick(nil, rand)
	log.ErrFatal(Write64Pub(s, b, p))
	log.ErrFatal(Write64Pub(s, b, p))
	p2, err := Read64Pub(s, b)
	log.ErrFatal(err)
	require.Equal(t, p, p2)
	p2, err = Read64Pub(s, b)
	log.ErrFatal(err)
	require.Equal(t, p, p2)
}

func TestScalar64(t *testing.T) {
	b := &bytes.Buffer{}
	rand := s.Cipher([]byte("example"))
	sc := s.Scalar().Pick(rand)
	log.ErrFatal(Write64Scalar(s, b, sc))
	log.ErrFatal(Write64Scalar(s, b, sc))
	s2, err := Read64Scalar(s, b)
	log.ErrFatal(err)
	require.True(t, sc.Equal(s2))
	s2, err = Read64Scalar(s, b)
	log.ErrFatal(err)
	require.True(t, sc.Equal(s2))
}

func TestPubHexStream(t *testing.T) {
	b := &bytes.Buffer{}
	rand := s.Cipher([]byte("example"))
	p, _ := s.Point().Pick(nil, rand)
	log.ErrFatal(WriteHexPub(s, b, p))
	log.ErrFatal(WriteHexPub(s, b, p))
	p2, err := ReadHexPub(s, b)
	log.ErrFatal(err)
	require.Equal(t, p, p2)
	p2, err = ReadHexPub(s, b)
	log.ErrFatal(err)
	require.Equal(t, p, p2)
}

func TestScalarHexStream(t *testing.T) {
	b := &bytes.Buffer{}
	rand := s.Cipher([]byte("example"))
	sc := s.Scalar().Pick(rand)
	log.ErrFatal(WriteHexScalar(s, b, sc))
	log.ErrFatal(WriteHexScalar(s, b, sc))
	s2, err := ReadHexScalar(s, b)
	log.ErrFatal(err)
	require.True(t, sc.Equal(s2))
	s2, err = ReadHexScalar(s, b)
	log.ErrFatal(err)
	require.True(t, sc.Equal(s2))
}

func TestPubHexString(t *testing.T) {
	rand := s.Cipher([]byte("example"))
	p, _ := s.Point().Pick(nil, rand)
	pstr, err := PubToStringHex(s, p)
	log.ErrFatal(err)
	p2, err := StringHexToPub(s, pstr)
	log.ErrFatal(err)
	require.Equal(t, p, p2)
}

func TestPub64String(t *testing.T) {
	rand := s.Cipher([]byte("example"))
	p, _ := s.Point().Pick(nil, rand)
	pstr, err := PubToString64(s, p)
	log.ErrFatal(err)
	p2, err := String64ToPub(s, pstr)
	log.ErrFatal(err)
	require.Equal(t, p, p2)
}

func TestScalarHexString(t *testing.T) {
	rand := s.Cipher([]byte("example"))
	sc := s.Scalar().Pick(rand)
	scstr, err := ScalarToStringHex(s, sc)
	log.ErrFatal(err)
	s2, err := StringHexToScalar(s, scstr)
	log.ErrFatal(err)
	require.True(t, sc.Equal(s2))
}

func TestScalar64String(t *testing.T) {
	rand := s.Cipher([]byte("example"))
	sc := s.Scalar().Pick(rand)
	scstr, err := ScalarToString64(s, sc)
	log.ErrFatal(err)
	s2, err := String64ToScalar(s, scstr)
	log.ErrFatal(err)
	require.True(t, sc.Equal(s2))
}
