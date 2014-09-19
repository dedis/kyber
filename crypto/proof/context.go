package proof


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
type ProverContext interface {
	Put(message interface{}) error 		// Send message to verifier
	PubRand(message...interface{}) error	// Get public randomness
	PriRand(message...interface{})		// Get private randomness
}

// ProverContext represents the abstract environment
// required by the verifier in a Sigma protocol.
type VerifierContext interface {
	Get(message interface{}) error		// Receive message from prover
	PubRand(message...interface{}) error	// Get public randomness
}

