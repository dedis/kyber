package proof

import (
	"bytes"
	"crypto/cipher"
	"dissent/crypto"
)


// Hash-based noninteractive Sigma-protocol prover context
type hashProver struct {
	suite crypto.Suite
	proof bytes.Buffer
	msg bytes.Buffer
	pubrand crypto.RandomReader
	prirand crypto.RandomReader
}

func newHashProver(suite crypto.Suite, protoName string,
			rand cipher.Stream) *hashProver {
	var sc hashProver
	sc.suite = suite
	sc.pubrand.Stream = crypto.HashStream(suite, []byte(protoName), nil)
	sc.prirand.Stream = rand
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
func (c *hashProver) PubRand(data...interface{}) error {
	c.consumeMsg()
	return crypto.Read(&c.pubrand, data, c.suite)
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
}

func newHashVerifier(suite crypto.Suite, protoName string,
			proof []byte) *hashVerifier {
	var c hashVerifier
	if _,err := c.proof.Write(proof); err != nil {
		panic("Buffer.Write failed")
	}
	c.suite = suite
	c.prbuf = c.proof.Bytes()
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
func (c *hashVerifier) PubRand(data...interface{}) error {
	c.consumeMsg()				// Stir in newly-read data
	return crypto.Read(&c.pubrand, data, c.suite)
}



// HashProve runs a given Sigma-protocol prover with a ProverContext
// that produces a non-interactive proof via the Fiat-Shamir heuristic.
// Returns a byte-slice containing the noninteractive proof on success,
// or an error in the case of failure.
//
// The optional protocolName is fed into the hash function used in the proof,
// so that a proof generated for a particular protocolName
// will verify successfully only if the verifier uses the same protocolName.
//
// The caller must provide a source of random entropy for the proof;
// this can be crypto.RandomStream to use fresh random bits,
// or a pseudorandom stream based on a secret seed
// to create deterministically reproducible proofs.
//
func HashProve(suite crypto.Suite, protocolName string, random cipher.Stream,
		prover Prover) ([]byte,error) {
	ctx := newHashProver(suite, protocolName, random)
	if e := func(ProverContext)error(prover)(ctx); e != nil {
		return nil,e
	}
	return ctx.Proof(),nil
}

// Verifies a hash-based noninteractive proof generated with HashProve.
// The suite and protocolName must be the same as those given to HashProve.
// Returns nil if the proof checks out, or an error on any failure.
func HashVerify(suite crypto.Suite, protocolName string,
		verifier Verifier, proof []byte) error {
	ctx := newHashVerifier(suite, protocolName, proof)
	return func(VerifierContext)error(verifier)(ctx)
}

