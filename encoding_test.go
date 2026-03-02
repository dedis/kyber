package kyber

import (
	"math"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.dedis.ch/kyber/v4/internal/protobuf"
)

type intWrapper struct {
	Value int
}
type int64Wrapper struct {
	Value int64
}

type int32Wrapper struct {
	Value int32
}
type uint32Wrapper struct {
	Value uint32
}

func TestIntAndInt64Encoding(t *testing.T) {
	a := intWrapper{Value: 10}
	b := int64Wrapper{Value: 10}

	aEncoded, err := protobuf.Encode(&a)
	require.NoError(t, err)
	bEncoded, err := protobuf.Encode(&b)
	require.NoError(t, err)

	assert.Equal(t, aEncoded, bEncoded)
}

func TestUInt32AndInt32Encoding(t *testing.T) {
	u := int32Wrapper{Value: 1}
	s := uint32Wrapper{Value: 1}
	uEncoded, err := protobuf.Encode(&s)
	require.NoError(t, err)

	sEncoded, err := protobuf.Encode(&u)
	require.NoError(t, err)
	assert.NotEqual(t, uEncoded, sEncoded)
}

func TestInt32AndIntEncoding(t *testing.T) {
	a := int32Wrapper{Value: 2}
	b := intWrapper{Value: 2}
	aEncoded, err := protobuf.Encode(&a)
	require.NoError(t, err)
	bEncoded, err := protobuf.Encode(&b)
	require.NoError(t, err)
	assert.Equal(t, aEncoded, bEncoded)
}

func TestInt32AndInt64Encoding(t *testing.T) {
	a := int32Wrapper{Value: math.MaxInt32}
	b := int64Wrapper{Value: math.MaxInt32}
	aEncoded, err := protobuf.Encode(&a)
	require.NoError(t, err)
	bEncoded, err := protobuf.Encode(&b)
	require.NoError(t, err)
	assert.Equal(t, aEncoded, bEncoded)

}

func TestInt64AndInt32Decoding(t *testing.T) {
	a := int64Wrapper{Value: 2}
	b := int32Wrapper{Value: 2}

	aEncoded, err := protobuf.Encode(&a)
	require.NoError(t, err)

	bEncoded, err := protobuf.Encode(&b)
	require.NoError(t, err)

	assert.Equal(t, aEncoded, bEncoded)

	var aDecoded int32Wrapper
	err = protobuf.Decode(aEncoded, &aDecoded)
	require.NoError(t, err)

	var bDecoded int32Wrapper
	err = protobuf.Decode(bEncoded, &bDecoded)
	require.NoError(t, err)

	assert.Equal(t, aDecoded.Value, bDecoded.Value)
}

// zig-zag encoding for signed integers, does it also happen with Kyber structs?
// varint encoding, is it a problem for constant-time, how is the data processed before being sent?
// we should not leak information about the numbers' size at transmission time

// NOTE: a lot of parts of the code (e.g. poly.go) use encoding/binary and encoding/hex instead of protobuf
