package proof

import (
	"bytes"
	"dissent/crypto"
)


// Prover represents the prover role in an arbitrary Sigma-protocol.
// A prover is simply a higher-order function that takes a ProverContext,
// runs the protocol while making calls to the ProverContext methods as needed,
// and returns nil on success or an error once the protocol run concludes.
// The resulting proof is embodied in the interactions with the ProverContext,
// but HashProve() may be used to encode the proof into a non-interactive proof
// using a hash function via the Fiat-Shamir heuristic.
type Prover func(ctx ProverContext) error

// Verifier represents the verifier role in an arbitrary Sigma-protocol.
// A verifier is a higher-order function tthat takes a VerifierContext,
// runs the protocol while making calls to VerifierContext methods as needed,
// and returns nil on success or an error once the protocol run concludes.
type Verifier func(ctx VerifierContext) error



// ProverContext represents the abstract environment
// required by the prover in a Sigma protocol.
// XXX PubRand should return error, since it may require communication
type ProverContext interface {
	Put(message interface{}) error 		// Send message to verifier
	PubRand(message...interface{})		// Get public randomness
	PriRand(message...interface{})		// Get private randomness
}

// ProverContext represents the abstract environment
// required by the verifier in a Sigma protocol.
// XXX PubRand should return error, since it may require communication
type VerifierContext interface {
	Get(message interface{}) error		// Receive message from prover
	PubRand(message...interface{})		// Get public randomness
}


// Hash-based noninteractive Sigma-protocol prover context
type hashProver struct {
	suite crypto.Suite
	proof bytes.Buffer
	msg bytes.Buffer
	pubrand crypto.RandomReader
	prirand crypto.RandomReader
}

func NewHashProver(suite crypto.Suite, protoName string) *hashProver {
	var sc hashProver
	sc.suite = suite
	sc.pubrand.Stream = crypto.HashStream(suite, []byte(protoName), nil)
	sc.prirand.Stream = crypto.RandomStream
	return &sc
}

func (c *hashProver) Put(message interface{}) error {
	return crypto.Write(&c.msg, message, c.suite)
}

func (c *hashProver) consumeMsg() {
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
func (c *hashProver) PubRand(data...interface{}) {
	c.consumeMsg()
	if err := crypto.Read(&c.pubrand, data, c.suite); err != nil {
		panic("error reading random stream: "+err.Error())
	}
}

// Get private randomness
func (c *hashProver) PriRand(data...interface{}) {
	if err := crypto.Read(&c.prirand, data, c.suite); err != nil {
		panic("error reading random stream: "+err.Error())
	}
}

// Obtain the encoded proof once the Sigma protocol is complete.
func (c *hashProver) Proof() []byte {
	c.consumeMsg()
	return c.proof.Bytes()
}



// Noninteractive Sigma-protocol verifier context
type hashVerifier struct {
	suite crypto.Suite
	proof bytes.Buffer	// Buffer with which to read the proof
	prbuf []byte		// Byte-slice underlying proof buffer
	pubrand crypto.RandomReader
	prirand crypto.RandomReader
}

func NewHashVerifier(suite crypto.Suite, protoName string,
			proof []byte) *hashVerifier {
	var c hashVerifier
	if _,err := c.proof.Write(proof); err != nil {
		panic("Buffer.Write failed")
	}
	c.suite = suite
	c.prbuf = c.proof.Bytes()
	c.prirand.Stream = crypto.RandomStream
	c.pubrand.Stream = crypto.HashStream(suite, []byte(protoName), nil)
	return &c
}

func (c *hashVerifier) consumeMsg() {
	l := len(c.prbuf) - c.proof.Len()	// How many bytes read?
	if l > 0 {
		// Stir consumed bytes into the public randomness pool 
		buf := c.prbuf[:l]
		c.pubrand.Stream = crypto.HashStream(c.suite, buf, c.pubrand)

		c.prbuf = c.proof.Bytes()	// Reset to remaining bytes
	}
}

// Read structured data from the proof
func (c *hashVerifier) Get(message interface{}) error {
	return crypto.Read(&c.proof, message, c.suite)
}

// Get public randomness that depends on every bit in the proof so far.
func (c *hashVerifier) PubRand(data...interface{}) {
	c.consumeMsg()				// Stir in newly-read data
	if err := crypto.Read(&c.pubrand, data, c.suite); err != nil {
		panic("error reading random stream: "+err.Error())
	}
}

// Get private randomness
func (c *hashVerifier) PriRand(data...interface{}) {
	if err := crypto.Read(&c.prirand, data, c.suite); err != nil {
		panic("error reading random stream: "+err.Error())
	}
}




// Create a hash-based noninteractive proof via a given Sigma-protocol prover.
func HashProve(suite crypto.Suite, protoName string,
		prover Prover) ([]byte,error) {
	ctx := NewHashProver(suite, protoName)
	if e := func(ProverContext)error(prover)(ctx); e != nil {
		return nil,e
	}
	return ctx.Proof(),nil
}

// Verify a hash-based noninteractive proof.
func HashVerify(suite crypto.Suite, protoName string,
		verifier Verifier, proof []byte) error {
	ctx := NewHashVerifier(suite, protoName, proof)
	return func(VerifierContext)error(verifier)(ctx)
}

