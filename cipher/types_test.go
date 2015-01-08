package cipher

import (
	"testing"
	"reflect"
)

func TestTypes(t *testing.T) {
	if HashType.Kind() != reflect.Interface {
		panic("wrong kind")
	}
}

