package protobuf

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

type ValueInt interface {
	Print() string
}

type A struct {
	Value int
}

func (a *A) MarshalBinary() ([]byte, error) {
	return []byte(fmt.Sprintf("%d", a.Value)), nil
}

func (a *A) Print() string {
	return ""
}

type B struct {
	AValue A
	AInt   int
}

func TestMarshal(t *testing.T) {
	var a A = A{0}
	var b B = B{a, 1}

	bufA, _ := Encode(&a)
	bufB, _ := Encode(&b)

	t.Log(bufA)
	t.Log(bufB)

	testA := A{}
	testB := B{}

	Decode(bufA, &testA)
	Decode(bufB, &testB)

	assert.Equal(t, testA, a)
	assert.Equal(t, testB, b)
}
