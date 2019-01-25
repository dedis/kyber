package ecies

import (
	"testing"

	"github.com/stretchr/testify/require"
	"go.dedis.ch/kyber/v3/group/edwards25519"
	"go.dedis.ch/kyber/v3/util/random"
)

func TestECIES(t *testing.T) {
	message := []byte("Hello ECIES")
	suite := edwards25519.NewBlakeSHA256Ed25519()
	private := suite.Scalar().Pick(random.New())
	public := suite.Point().Mul(private, nil)
	ciphertext, err := Encrypt(suite, public, message, suite.Hash)
	require.Nil(t, err)
	plaintext, err := Decrypt(suite, private, ciphertext, suite.Hash)
	require.Nil(t, err)
	require.Equal(t, message, plaintext)
}

func TestECIESFailPoint(t *testing.T) {
	message := []byte("Hello ECIES")
	suite := edwards25519.NewBlakeSHA256Ed25519()
	private := suite.Scalar().Pick(random.New())
	public := suite.Point().Mul(private, nil)
	ciphertext, err := Encrypt(suite, public, message, nil)
	require.Nil(t, err)
	ciphertext[0] ^= 0xff
	_, err = Decrypt(suite, private, ciphertext, nil)
	require.NotNil(t, err)
}

func TestECIESFailCiphertext(t *testing.T) {
	message := []byte("Hello ECIES")
	suite := edwards25519.NewBlakeSHA256Ed25519()
	private := suite.Scalar().Pick(random.New())
	public := suite.Point().Mul(private, nil)
	ciphertext, err := Encrypt(suite, public, message, nil)
	require.Nil(t, err)
	l := suite.PointLen()
	ciphertext[l] ^= 0xff
	_, err = Decrypt(suite, private, ciphertext, nil)
	require.NotNil(t, err)
}
