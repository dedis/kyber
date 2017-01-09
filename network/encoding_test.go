package network

import (
	"crypto/rand"
	"reflect"
	"testing"

	"github.com/satori/go.uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type TestRegisterS struct {
	I int
}

func TestRegister(t *testing.T) {
	if MessageType(&TestRegisterS{}) != ErrorType {
		t.Fatal("TestRegister should not yet be there")
	}

	trType := RegisterMessage(&TestRegisterS{})
	if uuid.Equal(uuid.UUID(trType), uuid.Nil) {
		t.Fatal("Couldn't register TestRegister-struct")
	}

	if MessageType(&TestRegisterS{}) != trType {
		t.Fatal("TestRegister is different now")
	}
	if MessageType(TestRegisterS{}) != trType {
		t.Fatal("TestRegister is different now")
	}
}

func TestUnmarshalRegister(t *testing.T) {
	constructors := DefaultConstructors(Suite)
	trType := RegisterMessage(&TestRegisterS{})
	buff, err := MarshalRegisteredType(&TestRegisterS{10})
	require.Nil(t, err)

	ty, b, err := UnmarshalRegisteredType(buff, constructors)
	assert.Nil(t, err)
	assert.Equal(t, trType, ty)
	assert.Equal(t, 10, b.(TestRegisterS).I)

	var randType [16]byte
	rand.Read(randType[:])
	buff = append(randType[:], buff[16:]...)
	ty, b, err = UnmarshalRegisteredType(buff, constructors)
	assert.NotNil(t, err)
	assert.Equal(t, ErrorType, ty)
}

func TestRegisterReflect(t *testing.T) {
	typ := RegisterMessage(TestRegisterS{})
	typReflect := RTypeToMessageTypeID(reflect.TypeOf(TestRegisterS{}))
	if typ != typReflect {
		t.Fatal("Register does not work")
	}
}
