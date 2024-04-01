package circl_bls12381

import (
	"testing"

	"github.com/stretchr/testify/require"
	"go.dedis.ch/kyber/v3/util/key"
)

func TestAdapter_SuiteBLS12381(t *testing.T) {
	suite := NewSuiteBLS12381()

	pair := key.NewKeyPair(suite)
	pubkey, err := pair.Public.MarshalBinary()
	require.Nil(t, err)
	privkey, err := pair.Private.MarshalBinary()
	require.Nil(t, err)

	pubhex := suite.Point()
	err = pubhex.UnmarshalBinary(pubkey)
	require.Nil(t, err)

	privhex := suite.Scalar()
	err = privhex.UnmarshalBinary(privkey)
	require.Nil(t, err)

	require.Equal(t, "bls12381.adapter", suite.String())
}
