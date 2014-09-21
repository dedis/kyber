package protobuf

import (
	"fmt"
	"bytes"
	"testing"
	//"encoding/hex"
)

type emb struct {
	I32 int32
	S string
}

type test struct {
	Bool bool
	I32 int32
	I64 int64
	U32 uint32
	U64 uint64
	F32 float32
	F64 float64
	Bytes []byte
	String string
	Struct emb

	OBool *bool
	OI32 *int32
	OI64 *int64
	OU32 *uint32
	OU64 *uint64
	OF32 *float32
	OF64 *float64
	OBytes *[]byte
	OString *string
	OStruct *test

	SBool []bool
	SI32 []int32
	SI64 []int64
	SU32 []uint32
	SU64 []uint64
	SF32 []float32
	SF64 []float64
	SBytes [][]byte
	SString []string
	SStruct []emb
}

func eqrep(i1,i2 interface{}) bool {
	return fmt.Sprintf("%v",i1) == fmt.Sprintf("%v",i2)
}
func (e1 *emb) equal(e2 *emb) bool {
	return	e1.I32 == e2.I32 &&
		e1.S == e2.S
}
func (t1 *test) equal(t2 *test) bool {
	return	t1.Bool == t2.Bool &&			// required fields
		t1.I32 == t2.I32 &&
		t1.I64 == t2.I64 &&
		t1.U32 == t2.U32 &&
		t1.U64 == t2.U64 &&
		t1.F32 == t2.F32 &&
		t1.F64 == t2.F64 &&
		bytes.Equal(t1.Bytes,t2.Bytes) &&
		t1.String == t2.String &&
		t1.Struct.equal(&t2.Struct) &&
		((t1.OBool == nil && t2.OBool == nil) ||	// optional
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
			bytes.Equal(*t1.OBytes,*t2.OBytes)) &&
		((t1.OString == nil && t2.OString == nil) ||
			(*t1.OString == *t2.OString)) &&
		((t1.OStruct == nil && t2.OStruct == nil) ||
			(*t1.OStruct).equal(t2.OStruct)) &&
		eqrep(t1.SBool,t2.SBool) &&			// repeated
		eqrep(t1.SI32,t2.SI32) &&
		eqrep(t1.SI64,t2.SI64) &&
		eqrep(t1.SU32,t2.SU32) &&
		eqrep(t1.SU64,t2.SU64) &&
		eqrep(t1.SF32,t2.SF32) &&
		eqrep(t1.SF64,t2.SF64) &&
		eqrep(t1.SBytes,t2.SBytes) &&
		eqrep(t1.SString,t2.SString) &&
		eqrep(t1.SStruct,t2.SStruct)
}

func TestProtobuf(t *testing.T) {

	b0 := bool(true)
	i1 := int32(-1)
	i2 := int64(-2)
	i3 := uint32(3)
	i4 := uint64(4)
	f5 := float32(5.5)
	f6 := float64(6.6)
	b7 := []byte("789")
	s8 := "ABC"
	e9 := test{}

	t1 := test{true,-1,-2,3,4,5.0,6.0,[]byte("789"),"abc",emb{123,"def"},
		&b0,&i1,&i2,&i3,&i4,&f5,&f6,&b7,&s8,&e9,
		[]bool{true,false,true},[]int32{1,-2,3},[]int64{2,-3,4},
		[]uint32{3,4,5},[]uint64{4,5,6},
		[]float32{5.5,6.6,7.7}, []float64{6.6,7.7,8.8},
		[][]byte{[]byte("abc"),[]byte("def")},
		[]string{"the","quick","brown","fox"},
		[]emb{emb{-1,"a"},emb{-2,"b"},emb{-3,"c"}},
	}
	buf := Encode(&t1)
	//fmt.Printf("Encoding:\n%s",hex.Dump(buf))

	t2 := test{}
	err := Decode(buf,&t2,nil)
	if err != nil {
		panic(err.Error())
	}

	if !t1.equal(&t2) {
		panic("decode didn't reproduce identical struct")
	}
}


type padded struct {
	Field1 int32		// = 1
	_ struct{}		// = 2
	Field3 int32		// = 3
	_ int			// = 4
	Field5 int32		// = 5
}

func TestPadded(t *testing.T) {
	t1 := padded{}
	t1.Field1 = 10
	t1.Field3 = 30
	t1.Field5 = 50
	buf := Encode(&t1)
	//fmt.Printf("Encoding:\n%s",hex.Dump(buf))

	t2 := padded{}
	err := Decode(buf,&t2,nil)
	if err != nil {
		panic(err.Error())
	}

	if t1 != t2 {
		panic("decode didn't reproduce identical struct")
	}
}

