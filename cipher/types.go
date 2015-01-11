// +build experimental

package cipher

import (
	"reflect"
	"github.com/dedis/crypto/abstract"
)

var stateVar abstract.Cipher
var hashVar Hash

var StateType = reflect.TypeOf(&stateVar).Elem()
var HashType = reflect.TypeOf(&hashVar).Elem()

