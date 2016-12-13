package network

import (
	"reflect"
	"testing"

	"github.com/satori/go.uuid"
)

type TestRegisterS struct {
	I int
}

func TestRegister(t *testing.T) {
	if TypeFromData(&TestRegisterS{}) != ErrorType {
		t.Fatal("TestRegister should not yet be there")
	}

	trType := RegisterPacketType(&TestRegisterS{})
	if uuid.Equal(uuid.UUID(trType), uuid.Nil) {
		t.Fatal("Couldn't register TestRegister-struct")
	}

	if TypeFromData(&TestRegisterS{}) != trType {
		t.Fatal("TestRegister is different now")
	}
	if TypeFromData(TestRegisterS{}) != trType {
		t.Fatal("TestRegister is different now")
	}
}

func TestRegisterReflect(t *testing.T) {
	typ := RegisterPacketType(TestRegisterS{})
	typReflect := RTypeToPacketTypeID(reflect.TypeOf(TestRegisterS{}))
	if typ != typReflect {
		t.Fatal("Register does not work")
	}
}
