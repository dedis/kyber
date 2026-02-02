package protobuf

import (
	"testing"

	"github.com/stretchr/testify/require"
)

type testInterface interface {
	String() string
}

type testStructA struct{}

func (a *testStructA) String() string {
	return "A"
}

func (a *testStructA) MarshalID() [8]byte {
	return [8]byte{'a'}
}

func (a *testStructA) MarshalBinary() ([]byte, error) {
	return nil, nil
}

type testStructB struct{}

func (b *testStructB) String() string {
	return "B"
}

func (b *testStructB) MarshalID() [8]byte {
	return [8]byte{'b'}
}

func (b *testStructB) MarshalBinary() ([]byte, error) {
	return nil, nil
}

func TestInterfaceRegistry(t *testing.T) {
	r := newInterfaceRegistry()

	r.register(func() interface{} { return &testStructA{} })
	r.register(func() interface{} { return &testStructB{} })

	require.NotNil(t, r.get(GeneratorID{'a'}))
	require.NotNil(t, r.get(GeneratorID{'b'}))
	require.Nil(t, r.get(GeneratorID{'c'}))
}
