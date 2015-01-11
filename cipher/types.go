// +build experimental

package cipher

import (
	"github.com/dedis/crypto/abstract"
	"reflect"
)

var stateVar abstract.Cipher
var hashVar Hash

var StateType = reflect.TypeOf(&stateVar).Elem()
var HashType = reflect.TypeOf(&hashVar).Elem()
