package cosi

import (
	"crypto/cipher"
	"crypto/sha512"
	"errors"

	"github.com/dedis/kyber/abstract"
)

func Commit(suite abstract.Suite, s cipher.Stream) (random abstract.Scalar, commitment abstract.Point) {
	var stream = s
	if s == nil {
		stream = random.Stream
	}
	random := suite.Scalar().Pick(stream)
	commitment := suite.Point().Mul(nil, random)
	return random, commitment
}

func AggregateCommitments(suite abstract.Suite, commitments []abstract.Point, masks []*Mask) (abstract.Point, *Mask, error) {

	if len(commitments) != len(masks) {
		return nil, nil, errors.New("length mismatch")
	}
	// TODO: check for empty value

	c := commitments[0]
	m := masks[0]
	for i := 1; i < len(commitments); i++ {
		c = suite.Point().Add(c, commitments[i])
		m.AggregateMasks(masks[i])
	}
	return c, m
}

func Challenge(suite abstract.Suite, commitment abstract.Point, mask *Mask, message []byte) (abstract.Scalar, error) {
	// return H(commitment || pubkey || mask || message)
	hash := sha512.New()
	if _, err := commitment.MarshalTo(hash); err != nil {
		return nil, err
	}
	if _, err := mask.AggregatePublic().MarshalTo(hash); err != nil {
		return nil, err
	}
	hash.Write(mask.mask)
	hash.Write(message)
	return suite.Scalar().SetBytes(hash.Sum(nil)), nil
}

func Response(suite abstract.Suite, random abstract.Scalar, challenge abstract.Scalar, prikey abstract.Scalar) (abstract.Scalar, error) {
	// return random - challenge * prikey

	if private == nil {
		return errors.New("no private key")
	}
	if random == nil {
		return errors.New("no random scalar")
	}
	if challenge == nil {
		return errors.New("no challenge")
	}

	ca := suite.Scalar().Mul(prikey, challenge)
	return r.Add(random, ca)
}

func AggregateResponses(suite abstract.Suite, responses []abstract.Scalar) abstract.Scalar {
	// sum up all responses and return the result
	if responses == nil {
		return errors.New("empty list of responses")
	}

	r := responses[0]
	for i := 1; i < len(responses); i++ {
		r = suite.Scalar().Add(r, responses[i])
	}
	return r
}

func Sign(suite abstract.Suite, commitment abstract.Point, response abstract.Scalar, mask *Mask) ([]byte, error) {
	// sig = V || R || bitmask
	lenV := c.suite.PointLen()
	lenSig := lenV + suite.ScalarLen()
	VB, err := commitment.MarshalBinary()
	if err != nil {
		return nil, errors.New("marshalling commitment failed")
	}
	RB, err := response.MarshalBinary()
	if err != nil {
		return nil, errors.New("marshalling signature failed")
	}
	sig := make([]byte, lenSig+mask.MaskLen())
	copy(sig[:], VB)
	copy(sig[lenV:lenSig], VR)
	copy(sig[lenSig:], mask.mask)
	return sig
}

func Verify(suite abstract.Suite, pubkeys []abstract.Point, message, sig []byte, policy Policy) error {
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
