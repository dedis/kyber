package protobuf

import (
	"reflect"
	"strings"
	"testing"
)

func TestConstructorString(t *testing.T) {
	c := &Constructors{
		reflect.TypeOf(int64(0)): func() interface{} { return int64(0) },
	}
	if !strings.HasPrefix(c.String(), "int64=>(func() interface {}") {
		t.Fatal("unexpected constructor string: ", c)
	}
}
