package network

import (
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type TestRegisterS1 struct {
	I int
}
type TestRegisterS2 struct {
	I int
}

func TestRegisterMessage(t *testing.T) {
	if !MessageType(&TestRegisterS1{}).Equal(ErrorType) {
		t.Fatal("TestRegister should not yet be there")
	}

	trType := RegisterMessage(&TestRegisterS1{})
	if trType.IsNil() {
		t.Fatal("Couldn't register TestRegister-struct")
	}

	if !MessageType(&TestRegisterS1{}).Equal(trType) {
		t.Fatal("TestRegister is different now")
	}
	if !MessageType(TestRegisterS1{}).Equal(trType) {
		t.Fatal("TestRegister is different now")
	}
}

func TestRegisterMessages(t *testing.T) {
	oldRegistry := registry
	registry = newTypeRegistry()
	types := RegisterMessages(&TestRegisterS1{}, &TestRegisterS2{})
	assert.True(t, MessageType(&TestRegisterS1{}).Equal(types[0]))
	assert.True(t, MessageType(&TestRegisterS2{}).Equal(types[1]))
	registry = oldRegistry
}

func TestUnmarshalRegister(t *testing.T) {
	trType := RegisterMessage(&TestRegisterS1{})
	buff, err := Marshal(&TestRegisterS1{10})
	require.Nil(t, err)

	ty, b, err := Unmarshal(buff)
	assert.Nil(t, err)
	assert.Equal(t, trType, ty)
	assert.Equal(t, 10, b.(*TestRegisterS1).I)

	var randType [16]byte
	rand.Read(randType[:])
	buff = append(randType[:], buff[16:]...)
	ty, b, err = Unmarshal(buff)
	assert.NotNil(t, err)
	assert.Equal(t, ErrorType, ty)
}
