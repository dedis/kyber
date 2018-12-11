package suites

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSuites_Find(t *testing.T) {
	ss := []string{
		"ed25519",
		"bn256.G1",
		"bn256.G2",
		"bn256.GT",
		"P256",
		"Residue512",
	}

	for _, name := range ss {
		s, err := Find(name)
		require.NotNil(t, s, "missing "+name)
		require.NoError(t, err)

		s = MustFind(name)
		require.NotNil(t, s, "missing "+name)
	}
}
