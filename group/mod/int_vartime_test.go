//go:build !constantTime

package mod

import (
	"github.com/stretchr/testify/require"
	"go.dedis.ch/kyber/v4/compatible"
	"testing"
)

func TestInit128bits(t *testing.T) {
	i := compatible.NewInt(0).Lsh(&compatible.NewInt(1).Int, 128)
	i = i.Sub(i, &compatible.NewInt(1).Int)
	m := compatible.FromBigInt(i, nil).ToCompatibleMod()

	i1 := NewInt(compatible.NewInt(1), m)
	// size in bytes
	require.Equal(t, 16, i1.MarshalSize())
}
