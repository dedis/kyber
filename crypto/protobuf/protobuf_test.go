package protobuf

import (
	"testing"
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

func TestProtobuf(t *testing.T) {

	b0 := bool(true)
	i1 := int32(1)
	i2 := int64(2)
	i3 := uint32(3)
	i4 := uint64(4)
	f5 := float32(5.5)
	f6 := float64(6.6)
	b7 := []byte("789")
	s8 := "ABC"
	e9 := test{}

	t1 := test{true,1,2,3,4,5.0,6.0,[]byte("789"),"abc",emb{123,"def"},
		&b0,&i1,&i2,&i3,&i4,&f5,&f6,&b7,&s8,&e9,
		[]bool{true,false,true},[]int32{1,2,3},[]int64{2,3,4},
		[]uint32{3,4,5},[]uint64{4,5,6},
		[]float32{5.5,6.6,7.7}, []float64{6.6,7.7,8.8},
		[][]byte{[]byte("abc"),[]byte("def")},
		[]string{"the","quick","brown","fox"},
		[]emb{emb{1,"a"},emb{2,"b"},emb{3,"c"}},
	}
	buf,err := Encode(&t1)
	if err != nil {
		panic(err.Error())
	}
	t2 := test{}
	if err := Decode(buf,&t2,nil); err != nil {
		panic(err.Error())
	}
}

