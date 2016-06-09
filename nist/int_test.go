package nist

import (
	"encoding/hex"
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestIntEndianBytes(t *testing.T) {
	modulo, err := hex.DecodeString("1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed")
	moduloI := new(big.Int).SetBytes(modulo)
	assert.Nil(t, err)
	v, err := hex.DecodeString("9e86dbc411ddeab7515cfadacc4516d00d6858a3c1ec4084c05ed27c36ada6")
	assert.Nil(t, err)

	i := new(Int).InitBytes(v, moduloI)

	assert.Equal(t, i.MarshalSize(), 32)
	assert.NotPanics(t, func() { i.LittleEndian(32, 32) })
}
