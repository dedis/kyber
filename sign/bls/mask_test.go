package bls

import (
	"testing"

	"github.com/stretchr/testify/require"
	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/kyber/v3/pairing"
	"go.dedis.ch/kyber/v3/util/key"
)

const n = 17

var suite = pairing.NewSuiteBn256()
var publics []kyber.Point

func init() {
	publics = make([]kyber.Point, n)

	for i := 0; i < n; i++ {
		kp := key.NewKeyPair(suite)
		publics[i] = kp.Public
	}
}

func TestMask_CreateMask(t *testing.T) {
	mask, err := NewMask(suite, publics, nil)
	require.NoError(t, err)

	require.Equal(t, 0, mask.CountEnabled())
	require.Equal(t, n, mask.CountTotal())
	require.Equal(t, n/8+1, mask.Len())
	require.Equal(t, uint8(0), mask.Mask()[0])

	mask, err = NewMask(suite, publics, publics[2])
	require.NoError(t, err)

	require.Equal(t, 1, mask.CountEnabled())
	require.Equal(t, uint8(0x4), mask.Mask()[0])

	mask, err = NewMask(suite, publics, suite.G1().Point())
	require.Error(t, err)
}

func TestMask_SetBit(t *testing.T) {
	mask, err := NewMask(suite, publics, publics[2])
	require.NoError(t, err)

	err = mask.SetBit(1, true)
	require.NoError(t, err)
	require.Equal(t, uint8(0x6), mask.Mask()[0])
	require.Equal(t, 2, len(mask.Participants()))

	err = mask.SetBit(2, false)
	require.NoError(t, err)
	require.Equal(t, uint8(0x2), mask.Mask()[0])
	require.Equal(t, 1, len(mask.Participants()))

	err = mask.SetBit(-1, true)
	require.Error(t, err)
	err = mask.SetBit(len(publics), true)
	require.Error(t, err)
}

func TestMask_SetAndMerge(t *testing.T) {
	mask, err := NewMask(suite, publics, publics[2])
	require.NoError(t, err)

	err = mask.SetMask([]byte{})
	require.Error(t, err)

	err = mask.SetMask([]byte{0, 0, 0})
	require.NoError(t, err)

	err = mask.Merge([]byte{})
	require.Error(t, err)

	err = mask.Merge([]byte{0x6, 0, 0})
	require.NoError(t, err)
	require.Equal(t, uint8(0x6), mask.Mask()[0])
}
