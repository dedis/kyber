package protobuf

import (
	"errors"
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
	var expectedError *DecodingFieldError
	if !errors.As(err, &expectedError) {
		assert.Fail(t, "Expected error \"appending to non-slice\"")
	}
}

func TestCrash2(t *testing.T) {
	in := []byte("\n\x00")

	var s t2
	err := Decode(in, &s)
	assert.NotNil(t, err)
	var expectedError *DecodingFieldError
	assert.ErrorAs(t, err, &expectedError)
}
