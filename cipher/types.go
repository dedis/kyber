package cipher

import (
	"reflect"
)

var stateVar State
var hashVar Hash

var StateType = reflect.TypeOf(&stateVar).Elem()
var HashType = reflect.TypeOf(&hashVar).Elem()


