package ecies

import (
	"testing"

	"github.com/dedis/kyber/pairing/bn256"
	"github.com/dedis/kyber/util/random"
	"github.com/stretchr/testify/require"
)

func TestECIES(t *testing.T) {
	message := []byte("shake that cipher")
	suite := bn256.NewSuite()
	private := suite.G2().Scalar().Pick(random.New())
	public := suite.G2().Point().Mul(private, nil)

	ephKey, ciphertext, err := Encrypt(suite.G2(), suite.Hash, public, message)
	require.Nil(t, err)

	plaintext, err := Decrypt(suite.G2(), suite.Hash, private, ephKey, ciphertext)
	require.Nil(t, err)

	require.Equal(t, message, plaintext)

}
