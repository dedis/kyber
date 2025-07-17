package proof

import (
	"bytes"
	"errors"
	"fmt"

	"go.dedis.ch/kyber/v4"
)

// DeniableProver is a Protocol implementing an interactive Sigma-protocol
// to prove a particular statement to the other participants.
// Optionally the Protocol participant can also verify
// the Sigma-protocol proofs of any or all of the other participants.
// Different participants may produce different proofs of varying sizes,
// and may even consist of different numbers of steps.
func DeniableProver(suite Suite, self int, prover Prover,
	verifiers []Verifier) Protocol {

	return func(ctx Context) []error {
		dp := deniableProver{}
		return dp.run(suite, self, prover, verifiers, ctx)
	}
}

type deniableProver struct {
	suite Suite   // Agreed-on ciphersuite for protocol
	self  int     // Our own node number
	sc    Context // Clique protocol context

	// verifiers for other nodes' proofs
	dv []*deniableVerifier

	// per-step state
	key  []byte        // Secret pre-challenge we committed to
	msg  *bytes.Buffer // Buffer in which to build prover msg
	msgs [][]byte      // All messages from last proof step

	pubrand kyber.XOF
	prirand kyber.XOF

	// Error/success indicators for all participants
	err []error
}

func (dp *deniableProver) run(suite Suite, self int, prv Prover,
	vrf []Verifier, sc Context) []error {
	dp.suite = suite
	dp.self = self
	dp.sc = sc
	dp.prirand = sc.Random()

	nnodes := len(vrf)
	if self < 0 || self >= nnodes {
		return []error{errors.New("out-of-range self node")}
	}

	// Initialize error slice entries to a default error indicator,
	// so that forgetting to run a verifier won't look like "success"
	verr := errors.New("prover or verifier not run")
	dp.err = make([]error, nnodes)
	for i := range dp.err {
		if i != self {
			dp.err[i] = verr
		}
	}

	// Launch goroutines to run whichever verifiers the caller requested
	dp.dv = make([]*deniableVerifier, nnodes)
	for i := range vrf {
		if vrf[i] != nil {
			dv := deniableVerifier{}
			dv.start(suite, vrf[i])
			dp.dv[i] = &dv
		}
	}

	// Run the prover, which will also drive the verifiers.
	err := dp.initStep()
	if err != nil {
		dp.err[self] = err
		return dp.err
	}

	if err := (func(ProverContext) error)(prv)(dp); err != nil {
		dp.err[self] = err
	}

	// Send the last prover message.
	// Make sure the verifiers get to run to completion as well
	for {
		stragglers, err := dp.proofStep()
		if err != nil {
			dp.err[self] = err
			break
		}
		if !stragglers {
			break
		}
		if err = dp.challengeStep(); err != nil {
			dp.err[self] = err
			break
		}
	}

	return dp.err
}

// keySize is arbitrary, make it long enough to seed the XOF
const keySize = 128

// Start the message buffer off in each step with a randomness commitment
func (dp *deniableProver) initStep() error {
	key := make([]byte, keySize) // secret random key
	_, err := dp.prirand.Read(key)
	if err != nil {
		return err
	}
	dp.key = key

	msg := make([]byte, keySize) // send commitment to it
	xof := dp.suite.XOF(key)
	_, err = xof.Read(msg)
	if err != nil {
		return err
	}
	dp.msg = bytes.NewBuffer(msg)

	// The Sigma-Prover will now append its proof content to dp.msg...
	return nil
}

func (dp *deniableProver) proofStep() (bool, error) {

	// Send the randomness commit and accumulated message to the leader,
	// and get all participants' commits, via our star-protocol context.
	msgs, err := dp.sc.Step(dp.msg.Bytes())
	if err != nil {
		return false, err
	}
	if !bytes.Equal(msgs[dp.self], dp.msg.Bytes()) {
		return false, errors.New("own messages were corrupted")
	}
	dp.msgs = msgs

	// Distribute this step's prover messages
	// to the relevant verifiers as well,
	// waking them up in the process so they can proceed.
	for i := range dp.dv {
		dv := dp.dv[i]
		if dv != nil && i < len(msgs) {
			dv.inbox <- msgs[i][keySize:] // send to verifier
		}
	}

	// Collect the verifiers' responses,
	// collecting error indicators from verifiers that are done.
	stragglers := false
	for i := range dp.dv { // collect verifier responses
		dv := dp.dv[i]
		if dv != nil {
			done := <-dv.done // get verifier response
			if done {         // verifier is done
				dp.err[i] = dv.err
				dp.dv[i] = nil
			} else { // verifier needs next challenge
				stragglers = true
			}
		}
	}
	return stragglers, nil
}

func (dp *deniableProver) challengeStep() error {

	// Send our challenge randomness to the leader, and collect all.
	keys, err := dp.sc.Step(dp.key)
	if err != nil {
		return err
	}

	// XOR together all the participants' randomness contributions,
	// check them against the respective commits,
	// and ensure ours is included to ensure deniability
	// (even if all others turn out to be maliciously generated).
	mix := make([]byte, keySize)
	for i := range keys {
		com := dp.msgs[i][:keySize] // node i's randomness commitment
		key := keys[i]              // node i's committed random key
		if len(com) < keySize || len(key) < keySize {
			continue // ignore participants who dropped out
		}
		chk := make([]byte, keySize)
		_, err := dp.suite.XOF(key).Read(chk)
		if err != nil {
			return err
		}

		if !bytes.Equal(com, chk) {
			return errors.New("wrong key for commit")
		}
		for j := 0; j < keySize; j++ { // mix in this key
			mix[j] ^= key[j]
		}
	}
	if len(keys) <= dp.self || !bytes.Equal(keys[dp.self], dp.key) {
		return errors.New("our own message was corrupted")
	}

	// Use the mix to produce the public randomness needed by the prover
	dp.pubrand = dp.suite.XOF(mix)

	// Distribute the master challenge to any verifiers waiting for it
	for i := range dp.dv {
		dv := dp.dv[i]
		if dv != nil {
			dv.inbox <- mix // so send it
		}
	}

	// Setup for the next proof step
	err = dp.initStep()
	return err
}

func (dp *deniableProver) Put(message interface{}) error {
	// Add onto accumulated prover message
	return dp.suite.Write(dp.msg, message)
}

// Prover will call this after Put()ing all commits for a given step,
// to get the master challenge to be used in its challenge/responses.
func (dp *deniableProver) PubRand(data ...interface{}) error {

	if _, err := dp.proofStep(); err != nil { // finish proof step
		return err
	}
	if err := dp.challengeStep(); err != nil { // run challenge step
		return err
	}
	return dp.suite.Read(dp.pubrand, data...)
}

// Get private randomness
func (dp *deniableProver) PriRand(data ...interface{}) error {
	if err := dp.suite.Read(dp.prirand, data...); err != nil {
		return fmt.Errorf("error reading random stream: %v", err.Error())
	}
	return nil
}

// Interactive Sigma-protocol verifier context.
// Acts as a slave to a deniableProver instance.
type deniableVerifier struct {
	suite Suite

	inbox chan []byte   // Channel for receiving proofs and challenges
	prbuf *bytes.Buffer // Buffer with which to read proof messages

	done chan bool // Channel for sending done status indicators
	err  error     // When done indicates verify error if non-nil

	pubrand kyber.XOF
}

func (dv *deniableVerifier) start(suite Suite, vrf Verifier) {
	dv.suite = suite
	dv.inbox = make(chan []byte)
	dv.done = make(chan bool)

	// Launch a concurrent goroutine to run this verifier
	go func() {
		// Await the prover's first message
		dv.getProof()

		// Run the verifier, providing dv as its context
		dv.err = (func(VerifierContext) error)(vrf)(dv)

		// Signal verifier termination
		dv.done <- true
	}()
}

func (dv *deniableVerifier) getProof() {
	// Get the next message from the prover
	prbuf := <-dv.inbox
	dv.prbuf = bytes.NewBuffer(prbuf)
}

// Read structured data from the proof
func (dv *deniableVerifier) Get(message interface{}) error {
	return dv.suite.Read(dv.prbuf, message)
}

// Get the next public random challenge.
func (dv *deniableVerifier) PubRand(data ...interface{}) error {

	// Signal that we need the next challenge
	dv.done <- false

	// Wait for it
	chal := <-dv.inbox

	// Produce the appropriate publicly random stream
	dv.pubrand = dv.suite.XOF(chal)
	if err := dv.suite.Read(dv.pubrand, data...); err != nil {
		return err
	}

	// Get the next proof message
	dv.getProof()
	return nil
}
