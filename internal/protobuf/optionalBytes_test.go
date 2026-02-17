package protobuf

import (
	"github.com/stretchr/testify/require"
	"testing"
)

type Pass struct {
	Other []int
}

type Fail struct {
	Bytes []byte
}

func TestOptionalBytes(t *testing.T) {
	buffP, errP := Encode(new(Pass))
	buffF, errF := Encode(new(Fail))

	bytes := []byte{1, 2, 3}
	buffFP, errFP := Encode(&Fail{bytes})

	t.Log(buffP, errP)
	t.Log(buffF, errF)
	t.Log(buffFP, errFP)

	require.Equal(t, buffF, buffP)
}
