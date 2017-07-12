package cosi

import (
	"crypto/cipher"

	"github.com/dedis/kyber/abstract"
)

func Commit(suite abstract.Suite, s cipher.Stream) (abstract.Scalar, abstract.Point) {
	// compute random scalar
	// compute commitment
	// return both
}

func AggregateCommitments(suite abstract.Suite, commitments []abstract.Point, mask *Mask) (abstract.Point, *Mask) {
	// sum up all commitments
	// update mask
	// return both
}

func Challenge(suite abstract.Suite, commitment abstract.Point, pubkey abstract.Point, mask, message []byte) abstract.Scalar {
	// return H(commitment || pubkey || mask || message)
}

func Response(suite abstract.Suite, random abstract.Scalar, challenge abstract.Scalar, prikey abstract.Scalar) {
	// return random - challenge * prikey
}

func AggregateResponses(suite abstract.Suite, responses []abstract.Scalar) abstract.Scalar {
	// sum up all responses and return the result
}

func Sign(suite abstract.Suite, commitment abstract.Point, response abstract.Scalar, mask *Mask) []byte {
	// marshal commitment
	// marshal response
	// put those two with the byte mask into a slice of bytes
	// return the latter as a signature
}

func Verify(suite abstract.Suite, pubkey abstract.Point, message, sig []byte, policy Policy) error {
	// verify sig on message
	// verify sig vs policy
}

type Mask struct {
	suite     abstract.Suite
	mask      []byte
	publics   []abstract.Point
	aggPublic abstract.Point
}

func NewMask(suite abstract.Suite, publics []abstract.Point) *Mask {
	// initialize an all empty mask struct and return it
	// by default all participants should be disabled; once they send a commitment they get enabled
}

func (m *Mask) SetMask(mask []byte) error {
	// set mask to the given one
	// update aggregate public key
}

func (m *Mask) SetBit(i int, val bool) error {
	// set the given bit in the mask to true (1) / false (0)
	// update aggregate public key
}

func (m *Mask) CountEnabled() int {
	// return the number of 1s in the mask
}

func (m *Mask) CountTotal() int {
	return m.len(publics)
}

func (m *Mask) Length() int {
	// return byte length of mask
}

func (m *Mask) AggregatePublic() abstract.Point {
	return m.aggPublic
}

func (m *Mask) AggregateMasks(other []byte) {
	// merge the other mask into m.mask via m.SetBit()
}

// Policy represents a fully customizable cosigning policy deciding what
// cosigner sets are and aren't sufficient for a collective signature to be
// considered acceptable to a verifier. The Check method may inspect the set of
// participants that cosigned by invoking cosi.Mask and/or cosi.MaskBit, and may
// use any other relevant contextual information (e.g., how security-critical
// the operation relying on the collective signature is) in determining whether
// the collective signature was produced by an acceptable set of cosigners.
type Policy interface {
	Check(m *Mask) bool
}

// CompletePolicy is the default policy requiring that all participants have
// cosigned to make a collective signature valid.
type CompletePolicy struct {
}

// Check verifies that all participants have contributed to a collective
// signature.
func (p CompletePolicy) Check(m *Mask) bool {
	return m.CountEnabled() == m.CountTotal()
}

// ThresholdPolicy allows to specify a simple t-of-n policy requring that at
// least the given threshold number of participants have cosigned to make a
// collective signature valid.
type ThresholdPolicy struct {
	t int
}

// Check verifies that at least a threshold number of participants have
// contributed to a collective signature.
func (p ThresholdPolicy) Check(m *Mask) bool {
	return m.CountEnabled() >= p.t
}

// SetPolicy allows to set a new policy for the given CoSi instance. By default
// it uses the complete policy.
func (c *CoSi) SetPolicy(policy Policy) {
	if policy == nil {
		c.policy = CompletePolicy{}
	} else {
		c.policy = policy
	}
}
