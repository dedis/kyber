//go:build !constantTime

package protobuf

import (
	"testing"

	"github.com/stretchr/testify/require"
	"go.dedis.ch/kyber/v4"
	"go.dedis.ch/kyber/v4/suites"
)

// TestInterfaceVartime runs the same test as TestInterface but using a suite available
// only in vartime (bn256)
func TestInterfaceVartime(t *testing.T) {
	type Points struct {
		P1 kyber.Point
		P2 kyber.Point
	}

	bn256 := suites.MustFind("bn256.adapter")
	ed25519 := suites.MustFind("ed25519")

	RegisterInterface(func() interface{} { return bn256.Point() })
	RegisterInterface(func() interface{} { return ed25519.Point() })

	pp := Points{
		P1: bn256.Point().Pick(bn256.XOF([]byte("test"))),
		P2: ed25519.Point().Pick(ed25519.XOF([]byte("test"))),
	}

	buf, err := Encode(&pp)
	require.NoError(t, err)

	var dpp Points
	err = Decode(buf, &dpp)
	require.NoError(t, err)
	require.Equal(t, pp.P1.String(), dpp.P1.String())
	require.Equal(t, pp.P2.String(), dpp.P2.String())
}
