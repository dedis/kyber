package util

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestConstantStream(t *testing.T) {
	seed := []byte("Hellothisismyfixedseed")
	stream := NewConstantStream(seed)

	b1 := make([]byte, len(seed))
	b2 := make([]byte, len(seed))

	stream.XORKeyStream(b1, b1)
	stream.XORKeyStream(b2, b2)

	assert.Equal(t, b1, b2)
}
