package cosi

import (
	"crypto/cipher"
	"crypto/sha512"
	"errors"
	"fmt"

	"github.com/dedis/kyber/abstract"
	"github.com/dedis/kyber/random"
)

func Commit(suite abstract.Suite, s cipher.Stream) (abstract.Scalar, abstract.Point) {
	var stream = s
	if s == nil {
		stream = random.Stream
	}
	random := suite.Scalar().Pick(stream)
	commitment := suite.Point().Mul(nil, random)
	return random, commitment
}

func AggregateCommitments(suite abstract.Suite, commitments []abstract.Point, masks [][]byte) (abstract.Point, []byte, error) {
	if len(commitments) != len(masks) {
		return nil, nil, errors.New("length mismatch")
	}
	// TODO: check that all masks have the same length
	// TODO: check for empty value
	aggCom := suite.Point().Null()
	aggMask := make([]byte, len(masks[0]))
	var err error
	for i := 0; i < len(commitments); i++ {
		aggCom = suite.Point().Add(aggCom, commitments[i])
		aggMask, err = AggregateMasks(aggMask, masks[i])
		if err != nil {
			return nil, nil, err
		}
	}
	return aggCom, aggMask, nil
}

func Challenge(suite abstract.Suite, commitment abstract.Point, mask *Mask, message []byte) (abstract.Scalar, error) {
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

func Response(suite abstract.Suite, random abstract.Scalar, challenge abstract.Scalar, private abstract.Scalar) (abstract.Scalar, error) {
	if private == nil {
		return nil, errors.New("no private key")
	}
	if random == nil {
		return nil, errors.New("no random scalar")
	}
	if challenge == nil {
		return nil, errors.New("no challenge")
	}
	ca := suite.Scalar().Mul(private, challenge)
	return ca.Add(random, ca), nil
}

func AggregateResponses(suite abstract.Suite, responses []abstract.Scalar) (abstract.Scalar, error) {
	if responses == nil {
		return nil, errors.New("empty list of responses")
	}
	r := responses[0]
	for i := 1; i < len(responses); i++ {
		r = suite.Scalar().Add(r, responses[i])
	}
	return r, nil
}

func Sign(suite abstract.Suite, commitment abstract.Point, response abstract.Scalar, mask *Mask) ([]byte, error) {
	lenV := suite.PointLen()
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
	copy(sig[lenV:lenSig], RB)
	copy(sig[lenSig:], mask.mask)
	return sig, nil
}

func Verify(suite abstract.Suite, publics []abstract.Point, message, sig []byte, policy Policy) error {
	lenCom := suite.PointLen()
	VBuff := sig[:lenCom]
	V := suite.Point()
	if err := V.UnmarshalBinary(VBuff); err != nil {
		panic(err)
	}

	// Unpack the aggregate response
	lenRes := lenCom + suite.ScalarLen()
	rBuff := sig[lenCom:lenRes]
	r := suite.Scalar().SetBytes(rBuff)

	// Unpack the participation mask and get the aggregate public key
	mask, err := NewMask(suite, publics, nil)
	if err != nil {
		return err
	}
	mask.SetMask(sig[lenRes:])
	A := mask.AggregatePublic()
	ABuff, err := A.MarshalBinary()
	if err != nil {
		return err
	}

	// Recompute the challenge
	hash := sha512.New()
	hash.Write(VBuff)
	hash.Write(ABuff)
	hash.Write(mask.mask)
	hash.Write(message)
	buff := hash.Sum(nil)
	k := suite.Scalar().SetBytes(buff)

	// k * -aggPublic + s * B = k*-A + s*B
	// from s = k * a + r => s * B = k * a * B + r * B <=> s*B = k*A + r*B
	// <=> s*B + k*-A = r*B
	minusPublic := suite.Point().Neg(A)
	kA := suite.Point().Mul(minusPublic, k)
	sB := suite.Point().Mul(nil, r)
	left := suite.Point().Add(kA, sB)

	// TODO: do constant time comparison
	if !left.Equal(V) || !policy.Check(mask) {
		return errors.New("signature invalid")
	}

	return nil
}

// mask represents a cosigning participation bit mask.
type Mask struct {
	mask      []byte
	publics   []abstract.Point
	aggPublic abstract.Point
	suite     abstract.Suite
}

// NewMask returns a new participation bit mask for cosigning where all
// cosigners are disabled by default.
func NewMask(suite abstract.Suite, publics []abstract.Point, myKey abstract.Point) (*Mask, error) {

	m := &Mask{
		publics: publics,
		suite:   suite,
	}
	m.mask = make([]byte, m.MaskLen())
	m.aggPublic = m.suite.Point().Null()

	if myKey != nil {
		found := false
		for i, key := range publics {
			if key.Equal(myKey) {
				m.SetMaskBit(i, true)
				found = true
				break
			}
		}
		if !found {
			return nil, errors.New("key not found")
		}
	}

	return m, nil
}

// Mask returns a copy of the participation bit mask.
func (m *Mask) Mask() []byte {
	clone := make([]byte, len(m.mask))
	copy(clone[:], m.mask)
	return clone
}

// SetMask sets the participation bit mask according to the given byte slice
// interpreted in little-endian order, i.e., bits 0-7 of byte 0 correspond to
// cosigners 0-7, bits 0-7 of byte 1 correspond to cosigners 8-15, etc.
func (m *Mask) SetMask(mask []byte) error {
	if m.MaskLen() != len(mask) {
		return fmt.Errorf("Mask length mismatch: %d vs %d", m.MaskLen(), len(mask))
	}
	for i := range m.publics {
		byt := i >> 3
		msk := byte(1) << uint(i&7)
		if ((m.mask[byt] & msk) == 0) && ((mask[byt] & msk) != 0) {
			m.mask[byt] ^= msk // flip bit in mask from 0 to 1
			m.aggPublic.Add(m.aggPublic, m.publics[i])
		}
		if ((m.mask[byt] & msk) != 0) && ((mask[byt] & msk) == 0) {
			m.mask[byt] ^= msk // flip bit in mask from 1 to 0
			m.aggPublic.Sub(m.aggPublic, m.publics[i])
		}
	}
	return nil
}

// MaskLen returns the mask length in bytes.
func (m *Mask) MaskLen() int {
	return (len(m.publics) + 7) >> 3
}

// SetMaskBit enables (enable: true) or disables (enable: false) the bit
// in the participation mask of the given cosigner.
func (m *Mask) SetMaskBit(signer int, enable bool) error {
	if signer > len(m.publics) {
		return errors.New("SetMaskBit index out of range")
	}
	byt := signer >> 3
	msk := byte(1) << uint(signer&7)
	if ((m.mask[byt] & msk) == 0) && enable {
		m.mask[byt] ^= msk // flip bit in mask from 0 to 1
		m.aggPublic.Add(m.aggPublic, m.publics[signer])
	}
	if ((m.mask[byt] & msk) != 0) && !enable {
		m.mask[byt] ^= msk // flip bit in mask from 1 to 0
		m.aggPublic.Sub(m.aggPublic, m.publics[signer])
	}
	return nil
}

// MaskBit returns a boolean value indicating whether the given signer is
// enabled (true) or disabled (false).
func (m *Mask) MaskBit(signer int) bool {
	if signer > len(m.publics) {
		return false // TODO: should this thrown an error? It was a panic before
	}
	byt := signer >> 3
	msk := byte(1) << uint(signer&7)
	return (m.mask[byt] & msk) != 0
}

// CountEnabled returns the number of enabled nodes in the CoSi participation
// mask, i.e., it returns the hamming weight of the mask.
func (m *Mask) CountEnabled() int {
	hw := 0
	for i := range m.publics {
		if m.MaskBit(i) {
			hw++
		}
	}
	return hw
}

// CountTotal returns the total number of nodes this CoSi instance knows.
func (m *Mask) CountTotal() int {
	return len(m.publics)
}

// Aggregate returns the aggregate public key of all *participating* signers.
func (m *Mask) AggregatePublic() abstract.Point {
	return m.aggPublic
}

func AggregateMasks(a, b []byte) ([]byte, error) {

	if len(a) != len(b) {
		return nil, errors.New("length mismatch")
	}

	m := make([]byte, len(a))
	for i := range m {
		m[i] = a[i] | b[i]
	}
	return m, nil

	// merge the other mask into m.mask
	//for i := range m.publics {
	//	byt := i >> 3
	//	msk := byte(1) << uint(i&7)
	//	if (other[byt] & msk) != 0 {
	//		m.SetMaskBit(i, true)
	//	}
	//}
	//return nil
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
