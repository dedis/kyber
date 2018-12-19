package edwards25519

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestPoint_Marshal(t *testing.T) {
	p := point{}
	require.Equal(t, "ed.point", fmt.Sprintf("%s", p.MarshalID()))
}
