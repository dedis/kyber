package abstract

import (
	"bytes"
	"fmt"
	"testing"
	//"time"	// XXX

	"github.com/stretchr/testify/assert"
	//"encoding/hex"
)

type emb struct {
	I32 int32
}

// test custom type-aliases
type mybool bool
type myint int
type myint32 int32
type myint64 int64
type myuint32 uint32
type myuint64 uint64
type myfloat32 float32
type myfloat64 float64
type mybytes []byte

// XXX 64-bit Unix time?

type test struct {
	Bool bool
	I    int
	I32  int32
	I64  int64
	U32  uint32
	U64  uint64
	F32  float32
	F64  float64

	Bytes   []byte
	Array   [3]byte
	Struct  emb
	StructP *emb
	SBool   []mybool
	SI32    []myint32
	SI64    []myint64
	SU32    []myuint32
	SU64    []myuint64
	SF32    []myfloat32
	SF64    []myfloat64
	SBytes  []mybytes
	SStruct []emb
}

func eqrep(i1, i2 interface{}) bool {
	return fmt.Sprintf("%v", i1) == fmt.Sprintf("%v", i2)
}
func (e1 *emb) equal(e2 *emb) bool {
	return e1.I32 == e2.I32
}
func (t1 *test) equal(t2 *test) bool {
	return t1.Bool == t2.Bool && // required fields
		t1.I == t2.I &&
		t1.I32 == t2.I32 &&
		t1.I64 == t2.I64 &&
		t1.U32 == t2.U32 &&
		t1.U64 == t2.U64 &&
		t1.F32 == t2.F32 &&
		t1.F64 == t2.F64 &&
		bytes.Equal(t1.Bytes, t2.Bytes) &&
		t1.Struct.equal(&t2.Struct) &&
		t1.StructP != nil && t2.StructP != nil &&
		t1.StructP.equal(t2.StructP) &&
		eqrep(t1.SBool, t2.SBool) && // repeated
		eqrep(t1.SI32, t2.SI32) &&
		eqrep(t1.SI64, t2.SI64) &&
		eqrep(t1.SU32, t2.SU32) &&
		eqrep(t1.SU64, t2.SU64) &&
		eqrep(t1.SF32, t2.SF32) &&
		eqrep(t1.SF64, t2.SF64) &&
		eqrep(t1.SBytes, t2.SBytes) &&
		eqrep(t1.SStruct, t2.SStruct) &&
		eqrep(t1.Array, t2.Array)
}

func TestEncoding(t *testing.T) {

	t1 := test{true, 0, -1, -2, 3, 4, 5.0, 6.0,
		[]byte("789"), [3]byte{1, 2, 3}, emb{123}, &emb{-1},
		[]mybool{true, false, true},
		[]myint32{1, -2, 3}, []myint64{2, -3, 4},
		[]myuint32{3, 4, 5}, []myuint64{4, 5, 6},
		[]myfloat32{5.5, 6.6, 7.7}, []myfloat64{6.6, 7.7, 8.8},
		[]mybytes{[]byte("abc"), []byte("def")},
		[]emb{emb{-1}, emb{-2}, emb{-3}},
	}
	var buf bytes.Buffer
	err := BinaryEncoding{}.Write(&buf, &t1)
	assert.NoError(t, err)
	//fmt.Printf("Encoding:\n%s",hex.Dump(buf))

	t2 := test{}
	t2.Bytes = make([]byte, 3)
	t2.SBool = make([]mybool, 3)
	t2.SI32 = make([]myint32, 3)
	t2.SI64 = make([]myint64, 3)
	t2.SU32 = make([]myuint32, 3)
	t2.SU64 = make([]myuint64, 3)
	t2.SF32 = make([]myfloat32, 3)
	t2.SF64 = make([]myfloat64, 3)
	t2.SBytes = make([]mybytes, 2)
	t2.SBytes[0] = make([]byte, 3)
	t2.SBytes[1] = make([]byte, 3)
	t2.SStruct = make([]emb, 3)

	err = BinaryEncoding{}.Read(&buf, &t2)
	assert.NoError(t, err)
	assert.Equal(t, t2, t1)

	overflow := int(0x100000000)
	defer func(t *testing.T) {
		if r := recover(); r == nil {
			t.Error("Putting a int > 32 bits into a int should have panicked")
		}
	}(t)
	var b bytes.Buffer
	err = BinaryEncoding{}.Write(&b, overflow)
	if err != nil {
		t.Error("Overflow int produced error ...?")
	}
}
