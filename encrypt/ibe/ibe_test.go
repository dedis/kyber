package ibe

import (
	"strings"
	"testing"

	"github.com/drand/kyber"
	bls "github.com/drand/kyber-bls12381"
	"github.com/drand/kyber/pairing"
	"github.com/drand/kyber/util/random"
	"github.com/stretchr/testify/require"
)

func newSetting() (pairing.Suite, kyber.Point, []byte, kyber.Point) {
	suite := bls.NewBLS12381Suite()
	P := suite.G1().Point().Base()
	s := suite.G1().Scalar().Pick(random.New())
	Ppub := suite.G1().Point().Mul(s, P)

	ID := []byte("passtherand")
	IDP := suite.G2().Point().(kyber.HashablePoint)
	Qid := IDP.Hash(ID)     // public key
	sQid := Qid.Mul(s, Qid) // secret key
	return suite, Ppub, ID, sQid
}

func TestValidTimelockEncryptionDecryptsCorrectly(t *testing.T) {
	suite, Ppub, ID, sQid := newSetting()
	msg := []byte("Hello World\n")

	c, err := Encrypt(suite, Ppub, ID, msg)
	require.NoError(t, err)
	msg2, err := Decrypt(suite, sQid, c)
	require.NoError(t, err)
	require.Equal(t, msg, msg2)
}

func TestInvalidSigmaFailsDecryption(t *testing.T) {
	suite, Ppub, ID, sQid := newSetting()
	msg := []byte("Hello World\n")

	c, err := Encrypt(suite, Ppub, ID, msg)
	require.NoError(t, err)

	c.V = []byte("somenonsense")

	_, err = Decrypt(suite, sQid, c)
	require.Error(t, err)
	require.ErrorContains(t, err, "invalid proof")
}

func TestInvalidMessageFailsDecryption(t *testing.T) {
	suite, Ppub, ID, sQid := newSetting()
	msg := []byte("Hello World\n")

	c, err := Encrypt(suite, Ppub, ID, msg)
	require.NoError(t, err)

	c.W = []byte("somenonsense")
	_, err = Decrypt(suite, sQid, c)
	require.Error(t, err)
	require.ErrorContains(t, err, "invalid proof")
}

func TestVeryLongInputFailsEncryption(t *testing.T) {
	suite, Ppub, ID, _ := newSetting()
	msg := []byte(strings.Repeat("And you have to understand this, that a prince, especially a new one, cannot observe all those things for which men are esteemed", 1000))
	_, err := Encrypt(suite, Ppub, ID, msg)
	require.Error(t, err)
}

func TestVeryLongCipherFailsDecryptionBecauseOfLength(t *testing.T) {
	suite, Ppub, ID, sQid := newSetting()
	msg := []byte("hello world")
	c, err := Encrypt(suite, Ppub, ID, msg)
	require.NoError(t, err)

	c.W = []byte(strings.Repeat("And you have to understand this, that a prince, especially a new one, cannot observe all those things for which men are esteemed", 1000))
	_, err = Decrypt(suite, sQid, c)

	require.Error(t, err)
	require.ErrorContains(t, err, "ciphertext too long for the hash function provided")
}

func TestInvalidWFailsDecryptionBecauseOfLength(t *testing.T) {
	suite, Ppub, ID, sQid := newSetting()
	msg := []byte("hello world")
	c, err := Encrypt(suite, Ppub, ID, msg)
	require.NoError(t, err)

	c.W = []byte(strings.Repeat("A", 25))
	_, err = Decrypt(suite, sQid, c)

	require.Error(t, err)
	require.ErrorContains(t, err, "XorSigma is of invalid length")
}
