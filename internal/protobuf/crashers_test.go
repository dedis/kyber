package protobuf

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// These are from fuzz.go, which found these problems.
type t1 [32]byte
type t2 struct {
	X, Y t1
	Sl   []bool
	T3   t3
	T3s  [3]t3
}
type t3 struct {
	I int
	F float64
	B bool
}

func TestCrash1(t *testing.T) {
	in := []byte("*\x00")

	// Found this former crasher while looking for the reason for
	// the next one.
	var i uint32
	err := Decode(in, &i)
	assert.NotNil(t, err)
	assert.Equal(t, err.Error(), "not a struct")

	var s t2
	err = Decode(in, &s)
	assert.NotNil(t, err)
	assert.Equal(t, "Error while decoding field {Name:T3s PkgPath: Type:[3]protobuf.t3 Tag: Offset:112 Index:[4] Anonymous:false}: append to non-slice", err.Error())
}

func TestCrash2(t *testing.T) {
	in := []byte("\n\x00")

	var s t2
	err := Decode(in, &s)
	assert.NotNil(t, err)
	assert.Equal(t, "Error while decoding field {Name:X PkgPath: Type:protobuf.t1 Tag: Offset:0 Index:[0] Anonymous:false}: array length and buffer length differ", err.Error())
}
