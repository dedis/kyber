package protobuf

import (
	"bytes"
	"fmt"
	"testing"
	//"encoding/hex"
)

type emb struct {
	I32 int32
	S   string
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
type mystring string

type test struct {
	Bool   bool
	I      int
	I32    int32
	I64    int64
	U32    uint32
	U64    uint64
	SX32   Sfixed32
	SX64   Sfixed64
	UX32   Ufixed32
	UX64   Ufixed64
	F32    float32
	F64    float64
	Bytes  []byte
	String string
	Struct emb

	OBool   *mybool
	OI32    *myint32
	OI64    *myint64
	OU32    *myuint32
	OU64    *myuint64
	OF32    *myfloat32
	OF64    *myfloat64
	OBytes  *mybytes
	OString *mystring
	OStruct *test

	SBool   []mybool
	SI32    []myint32
	SI64    []myint64
	SU32    []myuint32
	SU64    []myuint64
	SSX32   []Sfixed32
	SSX64   []Sfixed64
	SUX32   []Ufixed32
	SUX64   []Ufixed64
	SF32    []myfloat32
	SF64    []myfloat64
	SBytes  []mybytes
	SString []mystring
	SStruct []emb
}

func eqrep(i1, i2 interface{}) bool {
	return fmt.Sprintf("%v", i1) == fmt.Sprintf("%v", i2)
}
func (e1 *emb) equal(e2 *emb) bool {
	return e1.I32 == e2.I32 &&
		e1.S == e2.S
}
func (t1 *test) equal(t2 *test) bool {
	return t1.Bool == t2.Bool && // required fields
		t1.I == t2.I &&
		t1.I32 == t2.I32 &&
		t1.I64 == t2.I64 &&
		t1.U32 == t2.U32 &&
		t1.U64 == t2.U64 &&
		t1.SX32 == t2.SX32 &&
		t1.SX64 == t2.SX64 &&
		t1.UX32 == t2.UX32 &&
		t1.UX64 == t2.UX64 &&
		t1.F32 == t2.F32 &&
		t1.F64 == t2.F64 &&
		bytes.Equal(t1.Bytes, t2.Bytes) &&
		t1.String == t2.String &&
		t1.Struct.equal(&t2.Struct) &&
		((t1.OBool == nil && t2.OBool == nil) || // optional
			(*t1.OBool == *t2.OBool)) &&
		((t1.OI32 == nil && t2.OI32 == nil) ||
			(*t1.OI32 == *t2.OI32)) &&
		((t1.OI64 == nil && t2.OI64 == nil) ||
			(*t1.OI64 == *t2.OI64)) &&
		((t1.OU32 == nil && t2.OU32 == nil) ||
			(*t1.OU32 == *t2.OU32)) &&
		((t1.OU64 == nil && t2.OU64 == nil) ||
			(*t1.OU64 == *t2.OU64)) &&
		((t1.OF32 == nil && t2.OF32 == nil) ||
			(*t1.OF32 == *t2.OF32)) &&
		((t1.OF64 == nil && t2.OF64 == nil) ||
			(*t1.OF64 == *t2.OF64)) &&
		((t1.OBytes == nil && t2.OBytes == nil) ||
			bytes.Equal(*t1.OBytes, *t2.OBytes)) &&
		((t1.OString == nil && t2.OString == nil) ||
			(*t1.OString == *t2.OString)) &&
		((t1.OStruct == nil && t2.OStruct == nil) ||
			(*t1.OStruct).equal(t2.OStruct)) &&
		eqrep(t1.SBool, t2.SBool) && // repeated
		eqrep(t1.SI32, t2.SI32) &&
		eqrep(t1.SI64, t2.SI64) &&
		eqrep(t1.SU32, t2.SU32) &&
		eqrep(t1.SU64, t2.SU64) &&
		eqrep(t1.SSX32, t2.SSX32) &&
		eqrep(t1.SSX64, t2.SSX64) &&
		eqrep(t1.SUX32, t2.SUX32) &&
		eqrep(t1.SUX64, t2.SUX64) &&
		eqrep(t1.SF32, t2.SF32) &&
		eqrep(t1.SF64, t2.SF64) &&
		eqrep(t1.SBytes, t2.SBytes) &&
		eqrep(t1.SString, t2.SString) &&
		eqrep(t1.SStruct, t2.SStruct)
}

func TestProtobuf(t *testing.T) {

	b0 := mybool(true)
	i1 := myint32(-1)
	i2 := myint64(-2)
	i3 := myuint32(3)
	i4 := myuint64(4)
	f5 := myfloat32(5.5)
	f6 := myfloat64(6.6)
	b7 := mybytes("789")
	s8 := mystring("ABC")
	e9 := test{}

	t1 := test{true, 0, -1, -2, 3, 4, -11, -22, 33, 44, 5.0, 6.0,
		[]byte("789"), "abc", emb{123, "def"},
		&b0, &i1, &i2, &i3, &i4, &f5, &f6, &b7, &s8, &e9,
		[]mybool{true, false, true},
		[]myint32{1, -2, 3}, []myint64{2, -3, 4},
		[]myuint32{3, 4, 5}, []myuint64{4, 5, 6},
		[]Sfixed32{11, -22, 33}, []Sfixed64{22, -33, 44},
		[]Ufixed32{33, 44, 55}, []Ufixed64{44, 55, 66},
		[]myfloat32{5.5, 6.6, 7.7}, []myfloat64{6.6, 7.7, 8.8},
		[]mybytes{[]byte("abc"), []byte("def")},
		[]mystring{"the", "quick", "brown", "fox"},
		[]emb{emb{-1, "a"}, emb{-2, "b"}, emb{-3, "c"}},
	}
	buf := Encode(&t1)
	//fmt.Printf("Encoding:\n%s",hex.Dump(buf))

	t2 := test{}
	err := Decode(buf, &t2, nil)
	if err != nil {
		panic(err.Error())
	}

	//fmt.Printf("%v\n",t1)
	//fmt.Printf("%v\n",t2)
	if !t1.equal(&t2) {
		panic("decode didn't reproduce identical struct")
	}
}

type padded struct {
	Field1 int32    // = 1
	_      struct{} // = 2
	Field3 int32    // = 3
	_      int      // = 4
	Field5 int32    // = 5
}

func TestPadded(t *testing.T) {
	t1 := padded{}
	t1.Field1 = 10
	t1.Field3 = 30
	t1.Field5 = 50
	buf := Encode(&t1)
	//fmt.Printf("Encoding:\n%s",hex.Dump(buf))

	t2 := padded{}
	err := Decode(buf, &t2, nil)
	if err != nil {
		panic(err.Error())
	}

	if t1 != t2 {
		panic("decode didn't reproduce identical struct")
	}
}
