package nist

import (
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestIntEndianness(t *testing.T) {
	modulo := big.NewInt(65535)
	var v int64 = 65500
	// Let's assume it is bigendian and test that
	i := new(Int).Init64(v, modulo)
	assert.Equal(t, i.Bo, BigEndian)

	buff1, err := i.MarshalBinary()
	assert.Nil(t, err)
	i.Bo = BigEndian
	buff2, err := i.MarshalBinary()
	assert.Nil(t, err)
	assert.Equal(t, buff1, buff2)

	// Let's change endianness and check the result
	i.Bo = LittleEndian
	buff3, err := i.MarshalBinary()
	assert.NotEqual(t, buff2, buff3)

	// let's try LittleEndian function
	buff4 := i.LittleEndian(0, 32)
	assert.Equal(t, buff3, buff4)
	// set endianess but using littleendian should not change anything
	i.Bo = BigEndian
	assert.Equal(t, buff4, i.LittleEndian(0, 32))

	// Try to reconstruct the int from the buffer
	i = new(Int).Init64(v, modulo)
	i2 := NewInt(0, modulo)
	buff, _ := i.MarshalBinary()
	assert.Nil(t, i2.UnmarshalBinary(buff))
	assert.True(t, i.Equal(i2))

	i.Bo = LittleEndian
	buff, _ = i.MarshalBinary()
	i2.Bo = LittleEndian
	assert.Nil(t, i2.UnmarshalBinary(buff))
	assert.True(t, i.Equal(i2))

	i2.Bo = BigEndian
	assert.Nil(t, i2.UnmarshalBinary(buff))
	assert.False(t, i.Equal(i2))
}
