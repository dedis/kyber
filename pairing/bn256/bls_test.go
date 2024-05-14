package bn256

import (
	"testing"

	"github.com/stretchr/testify/require"
	"go.dedis.ch/kyber/v3/internal/test"
	"go.dedis.ch/kyber/v3/sign/bls"
	"go.dedis.ch/kyber/v3/util/random"
)

func TestBLSSchemeBN256G1(t *testing.T) {
	suite := NewSuite()
	s := bls.NewSchemeOnG1(suite)
	test.SchemeTesting(t, s)
}

func TestBinaryMarshalAfterAggregation_issue400(t *testing.T) {
	suite := NewSuite()
	s := bls.NewSchemeOnG1(suite)
	_, public1 := s.NewKeyPair(random.New())
	_, public2 := s.NewKeyPair(random.New())

	workingKey := s.AggregatePublicKeys(public1, public2, public1)

	workingBits, err := workingKey.MarshalBinary()
	require.Nil(t, err)

	workingPoint := suite.G2().Point()
	err = workingPoint.UnmarshalBinary(workingBits)
	require.Nil(t, err)

	// this was failing before the fix
	aggregatedKey := s.AggregatePublicKeys(public1, public1, public2)

	bits, err := aggregatedKey.MarshalBinary()
	require.Nil(t, err)

	point := suite.G2().Point()
	err = point.UnmarshalBinary(bits)
	require.Nil(t, err)
}
