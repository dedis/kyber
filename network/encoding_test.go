package network

import (
	"crypto/rand"
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
	trType := RegisterMessage(&TestRegisterS{})
	buff, err := Marshal(&TestRegisterS{10})
	require.Nil(t, err)

	ty, b, err := Unmarshal(buff)
	assert.Nil(t, err)
	assert.Equal(t, trType, ty)
	assert.Equal(t, 10, b.(*TestRegisterS).I)

	var randType [16]byte
	rand.Read(randType[:])
	buff = append(randType[:], buff[16:]...)
	ty, b, err = Unmarshal(buff)
	assert.NotNil(t, err)
	assert.Equal(t, ErrorType, ty)
}
