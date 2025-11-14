package kyber

import (
	"fmt"
	"github.com/stretchr/testify/assert"
	"go.dedis.ch/protobuf"
	"math"
	"testing"
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
	if err != nil {
		t.Fatal(err)
	}
	bEncoded, err := protobuf.Encode(&b)
	if err != nil {
		t.Fatal(err)
	}

	assert.Equal(t, aEncoded, bEncoded)
}

func TestUInt32AndInt32Encoding(t *testing.T) {
	u := int32Wrapper{Value: 1}
	s := uint32Wrapper{Value: 1}
	uEncoded, err := protobuf.Encode(&s)
	if err != nil {
		t.Fatal(err)
	}

	sEncoded, err := protobuf.Encode(&u)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Println("u : ", uEncoded, "s : ", sEncoded)

	assert.Equal(t, uEncoded, sEncoded)
}

func TestInt32AndIntEncoding(t *testing.T) {
	a := int32Wrapper{Value: 2}
	b := intWrapper{Value: 2}
	aEncoded, err := protobuf.Encode(&a)
	if err != nil {
		t.Fatal(err)
	}
	bEncoded, err := protobuf.Encode(&b)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Println("a : ", aEncoded, "b : ", bEncoded)
	assert.Equal(t, aEncoded, bEncoded)
}

func TestInt32AndInt64Encoding(t *testing.T) {
	a := int32Wrapper{Value: math.MaxInt32}
	b := int64Wrapper{Value: math.MaxInt32}
	aEncoded, err := protobuf.Encode(&a)
	if err != nil {
		t.Fatal(err)
	}
	bEncoded, err := protobuf.Encode(&b)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Println("a : ", aEncoded, "b : ", bEncoded)
	assert.Equal(t, aEncoded, bEncoded)

}

func TestInt64AndIntDecoding(t *testing.T) {
	a := int64Wrapper{Value: 2}
	b := intWrapper{Value: 2}
	aEncoded, err := protobuf.Encode(&a)
	if err != nil {
		t.Fatal(err)
	}
	bEncoded, err := protobuf.Encode(&b)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Println("a : ", aEncoded, "b : ", bEncoded)
	assert.Equal(t, aEncoded, bEncoded)

	var aDecoded intWrapper
	err = protobuf.Decode(aEncoded, &aDecoded)
	if err != nil {
		t.Fatal(err)
	}

	var bDecoded intWrapper
	err = protobuf.Decode(bEncoded, &bDecoded)
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, aDecoded.Value, bDecoded.Value)
	//assert.Equal(t, aDecoded.Value, b.Value)
}

//func TestBinaryInt64AndIntEncoding(t *testing.T) {
//	a := int64Wrapper{Value: 2}
//	b := intWrapper{Value: 2}
//	aEncoded, err := protobuf.Encode(&a)
//	if err != nil {
//		t.Fatal(err)
//	}
//	bEncoded, err := protobuf.Encode(&b)
//	if err != nil {
//		t.Fatal(err)
//	}
//
//	f, err := os.OpenFile("/123.txt", os.O_RDWR|os.O_CREATE|os.O_APPEND, 0600)
//	if err != nil {
//		panic(err)
//	}
//	defer f.Close()
//	err = binary.Write(f, binary.LittleEndian, aEncoded)
//	if err != nil {
//		panic(err)
//	}
//	err = binary.Write(f, binary.LittleEndian, bEncoded)
//	if err != nil {
//		panic(err)
//	}
//	f.
//}

// zig-zag encoding for signed integers, does it also happen with Kyber structs?
// varint encoding, is it a problem for constant-time, how is the data processed before being sent?
// we should not leak information about the numbers' size at transmission time

// NOTE: a lot of parts of the code (e.g. poly.go) use encoding/binary and encoding/hex instead of protobuf
