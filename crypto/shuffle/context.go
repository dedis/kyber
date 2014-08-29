package shuffle

import (
//	"io"
	"bytes"
//	"errors"
//	"reflect"
//	"crypto/cipher"
	"dissent/crypto"
)



/*
func Read (r io.Reader, data interface{}) error {

	// XXX deal with basic fixed-length types as in encoding/binary?

	if s,ok := data.(crypto.Secret); ok {
		
	}
}
*/


// ProverContext represents the abstract environment
// required by the prover in a Sigma protocol.
type ProverContext interface {
	Put(message interface{}) error 		// Send message to verifier
	PubRand(message...interface{})		// Get public randomness
	PriRand(message...interface{})		// Get private randomness
}

// ProverContext represents the abstract environment
// required by the verifier in a Sigma protocol.
type VerifierContext interface {
	Get(message interface{}) error		// Receive message from prover
	PubRand(message...interface{})		// Get public randomness
}


// Noninteractive Sigma-protocol prover context
type sigmaProver struct {
	suite crypto.Suite
	proof bytes.Buffer
	msg bytes.Buffer
	pubrand crypto.RandomReader
	prirand crypto.RandomReader
}

func newSigmaProver(suite crypto.Suite, protoName string) *sigmaProver {
	var sc sigmaProver
	sc.suite = suite
	sc.pubrand.Stream = crypto.HashStream(suite, []byte(protoName), nil)
	sc.prirand.Stream = crypto.RandomStream
	return &sc
}

func (c *sigmaProver) Put(message interface{}) error {
	return crypto.Write(&c.msg, message, c.suite)
}

func (c *sigmaProver) consumeMsg() {
	if c.msg.Len() > 0 {

		// Stir the message into the public randomness pool 
		buf := c.msg.Bytes()
		c.pubrand.Stream = crypto.HashStream(c.suite, buf, c.pubrand)

		// Append the current message data to the proof
		c.proof.Write(buf)
		c.msg.Reset()
	}
}

// Get public randomness that depends on every bit in the proof so far.
func (c *sigmaProver) PubRand(data...interface{}) {
	c.consumeMsg()
	if err := crypto.Read(&c.pubrand, data, c.suite); err != nil {
		panic("error reading random stream: "+err.Error())
	}
}

// Get private randomness
func (c *sigmaProver) PriRand(data...interface{}) {
	if err := crypto.Read(&c.prirand, data, c.suite); err != nil {
		panic("error reading random stream: "+err.Error())
	}
}

// Obtain the encoded proof once the Sigma protocol is complete.
func (c *sigmaProver) Proof() []byte {
	c.consumeMsg()
	return c.proof.Bytes()
}



// Noninteractive Sigma-protocol verifier context
type sigmaVerifier struct {
	suite crypto.Suite
	proof bytes.Buffer	// Buffer with which to read the proof
	prbuf []byte		// Byte-slice underlying proof buffer
	pubrand crypto.RandomReader
	prirand crypto.RandomReader
}

func newSigmaVerifier(suite crypto.Suite, protoName string,
			proof []byte) *sigmaVerifier {
	var c sigmaVerifier
	if _,err := c.proof.Write(proof); err != nil {
		panic("Buffer.Write failed")
	}
	c.suite = suite
	c.prbuf = c.proof.Bytes()
	c.prirand.Stream = crypto.RandomStream
	c.pubrand.Stream = crypto.HashStream(suite, []byte(protoName), nil)
	return &c
}

func (c *sigmaVerifier) consumeMsg() {
	l := len(c.prbuf) - c.proof.Len()	// How many bytes read?
	if l > 0 {
		// Stir consumed bytes into the public randomness pool 
		buf := c.prbuf[:l]
		c.pubrand.Stream = crypto.HashStream(c.suite, buf, c.pubrand)

		c.prbuf = c.proof.Bytes()	// Reset to remaining bytes
	}
}

// Read structured data from the proof
func (c *sigmaVerifier) Get(message interface{}) error {
	return crypto.Read(&c.proof, message, c.suite)
}

// Get public randomness that depends on every bit in the proof so far.
func (c *sigmaVerifier) PubRand(data...interface{}) {
	c.consumeMsg()				// Stir in newly-read data
	if err := crypto.Read(&c.pubrand, data, c.suite); err != nil {
		panic("error reading random stream: "+err.Error())
	}
}

// Get private randomness
func (c *sigmaVerifier) PriRand(data...interface{}) {
	if err := crypto.Read(&c.prirand, data, c.suite); err != nil {
		panic("error reading random stream: "+err.Error())
	}
}


