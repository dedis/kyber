package shuffle

import (
//	"io"
//	"errors"
//	"reflect"
	"crypto/cipher"
//	"dissent/crypto"
)



/*
func Read (r io.Reader, data interface{}) error {

	// XXX deal with basic fixed-length types as in encoding/binary?

	if s,ok := data.(crypto.Secret); ok {
		
	}
}
*/


// Generic interface representing the environmental context
// or "support wrapper" around a particular party in a protocol.
type Context interface {
	Put(message interface{})	// Send message
	Get(message interface{})	// Receive message
	PubRand(message...interface{})	// Get public randomness
	PriRand(message...interface{})	// Get private randomness
}


type sigmaContext struct {
	proof []byte
	pubrand, prirand cipher.Stream
}

func (c *sigmaContext) Put(message interface{}) {
}

func (c *sigmaContext) Get(message interface{}) {
}

func (c *sigmaContext) PubRand(data...interface{}) {
//	for d := range(data) {
//		
//	}
}

func (c *sigmaContext) PriRand(data...interface{}) {
}


/*
func SigmaProverContext(suite crypto.Suite, rand cipher.Stream) Context {
}

func SigmaVerifierContext(suite crypto.Suite, rand cipher.Stream) Context {
}
*/

