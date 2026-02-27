package protobuf

import (
	"encoding/hex"
	"math"
	"reflect"
	"testing"

	"github.com/stretchr/testify/require"
)

type ArrayTest1 struct {
	A []int64
}

type ArrayTest2 struct {
	A []int32
}

func TestArray(t *testing.T) {
	var maxInt32 int32 = math.MaxInt32
	var maxInt64 int64 = math.MaxInt64 / 2

	a1 := ArrayTest1{[]int64{1, 1, 1}}
	a2 := ArrayTest2{[]int32{1, 1, 1}}
	a3 := ArrayTest2{[]int32{1, 1, maxInt32}}
	a4 := ArrayTest1{[]int64{1, 1, maxInt64}}

	buf1, err := Encode(&a1)
	require.NoError(t, err)
	buf2, err := Encode(&a2)
	require.NoError(t, err)
	buf3, err := Encode(&a3)
	require.NoError(t, err)
	buf4, err := Encode(&a4)
	require.NoError(t, err)

	t.Log(hex.Dump(buf1))
	t.Log(hex.Dump(buf2))
	t.Log(hex.Dump(buf3))
	t.Log(hex.Dump(buf4))

	b1 := ArrayTest1{}
	b2 := ArrayTest2{}
	b3 := ArrayTest2{}
	b4 := ArrayTest1{}

	err = Decode(buf1, &b1)
	require.NoError(t, err)
	t.Log(b1, reflect.TypeOf(b1))

	err = Decode(buf2, &b2)
	require.NoError(t, err)
	t.Log(b2, reflect.TypeOf(b2))

	err = Decode(buf3, &b3)
	require.NoError(t, err)
	t.Log(b3, reflect.TypeOf(b3))

	err = Decode(buf4, &b4)
	require.NoError(t, err)
	t.Log(b4, reflect.TypeOf(b4))

	require.Equal(t, a1, b1)
	require.Equal(t, a2, b2)
	require.Equal(t, a3, b3)
	require.Equal(t, a4, b4)
}
