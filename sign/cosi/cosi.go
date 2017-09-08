/*
Package cosi implements the collective signing (CoSi) algorithm as presented in
the paper "Keeping Authorities 'Honest or Bust' with Decentralized Witness
Cosigning" by Ewa Syta et al., see https://arxiv.org/abs/1503.08768.  This
package **only** provides the functionality for the cryptographic operations of
CoSi. All network-related operations have to be handled elsewhere.  Below we
describe a high-level overview of the CoSi protocol (using a star communication
topology). We refer to the research paper for further details on communication
over trees, exception mechanisms and signature verification policies.

The CoSi protocol has four phases executed between a list of participants P
having a protocol leader (index i = 0) and a list of other nodes (index i > 0).
The secret key of node i is denoted by a_i and the public key by A_i = [a_i]G
(where G is the base point of the underlying group and [...] denotes scalar
multiplication). The aggregate public key is given as A = \sum{i ∈ P}(A_i).

1. Announcement: The leader broadcasts an announcement to the other nodes
optionally including the message M to be signed. Upon receiving an announcement
message, a node starts its commitment phase.

2. Commitment: Each node i (including the leader) picks a random scalar v_i,
computes its commitment V_i = [v_i]G and sends V_i back to the leader. The
leader waits until it has received enough commitments (according to some
policy) from the other nodes or a timer has run out. Let P' be the nodes that
have sent their commitments. The leader computes an aggregate commitment V from
all commitments he has received, i.e., V = \sum{j ∈ P'}(V_j) and creates a
participation bitmask Z. The leader then broadcasts V and Z to the other
participations together with the message M if it was not sent in phase 1. Upon
receiving a commitment message, a node starts the challenge phase.

3. Challenge: Each node i computes the collective challenge c = H(V || A || M)
using a cryptographic hash function H (here: SHA512), computes its
response r_i = v_i + c*a_i and sends it back to the leader.

4. Response: The leader waits until he has received replies from all nodes in
P' or a timer has run out. If he has not enough replies he aborts. Finally,
the leader computes the aggregate response r = \sum{j ∈ P'}(r_j) and publishes
(V,r,Z) as the signature for the message M.
*/
package cosi

import (
	"crypto/cipher"
	"crypto/sha512"
	"crypto/subtle"
	"errors"
	"fmt"

	"gopkg.in/dedis/kyber.v1"
	"gopkg.in/dedis/kyber.v1/util/random"
)

// Commit returns a random scalar v, generated from the given cipher stream,
// and a corresponding commitment V = [v]G. If the given cipher stream is nil,
// a random stream is used.
func Commit(group kyber.Group, s cipher.Stream) (kyber.Scalar, kyber.Point) {
	if s == nil {
		s = random.Stream
	}
	random := group.Scalar().Pick(s)
	commitment := group.Point().Mul(random, nil)
	return random, commitment
}

// AggregateCommitments returns the sum of the given commitments and the
// bitwise OR of the corresponding masks.
func AggregateCommitments(group kyber.Group, commitments []kyber.Point, masks [][]byte) (kyber.Point, []byte, error) {
	if len(commitments) != len(masks) {
		return nil, nil, errors.New("mismatching lengths of commitment and mask slices")
	}
	aggCom := group.Point().Null()
	aggMask := make([]byte, len(masks[0]))
	var err error
	for i := range commitments {
		aggCom = group.Point().Add(aggCom, commitments[i])
		aggMask, err = AggregateMasks(aggMask, masks[i])
		if err != nil {
			return nil, nil, err
		}
	}
	return aggCom, aggMask, nil
}

// Challenge creates the collective challenge from the given aggregate
// commitment V, aggregate public key A, and message M, i.e., it returns
// c = H(V || A || M).
func Challenge(group kyber.Group, commitment, public kyber.Point, message []byte) (kyber.Scalar, error) {
	if commitment == nil {
		return nil, errors.New("no commitment provided")
	}
	if message == nil {
		return nil, errors.New("no message provided")
	}
	hash := sha512.New()
	if _, err := commitment.MarshalTo(hash); err != nil {
		return nil, err
	}
	if _, err := public.MarshalTo(hash); err != nil {
		return nil, err
	}
	hash.Write(message)
	return group.Scalar().SetBytes(hash.Sum(nil)), nil
}

// Response creates the response from the given random scalar v, (collective)
// challenge c, and private key a, i.e., it returns r = v + c*a.
func Response(group kyber.Group, private, random, challenge kyber.Scalar) (kyber.Scalar, error) {
	if private == nil {
		return nil, errors.New("no private key provided")
	}
	if random == nil {
		return nil, errors.New("no random scalar provided")
	}
	if challenge == nil {
		return nil, errors.New("no challenge provided")
	}
	ca := group.Scalar().Mul(private, challenge)
	return ca.Add(random, ca), nil
}

// AggregateResponses returns the sum of given responses.
func AggregateResponses(group kyber.Group, responses []kyber.Scalar) (kyber.Scalar, error) {
	if responses == nil {
		return nil, errors.New("no responses provided")
	}
	r := group.Scalar().Zero()
	for i := range responses {
		r = r.Add(r, responses[i])
	}
	return r, nil
}

// Sign returns the collective signature from the given (aggregate) commitment
// V, (aggregate) response r, and participation bitmask Z using the EdDSA
// format, i.e., the signature is V || r || Z.
func Sign(group kyber.Group, commitment kyber.Point, response kyber.Scalar, mask *Mask) ([]byte, error) {
	if commitment == nil {
		return nil, errors.New("no commitment provided")
	}
	if response == nil {
		return nil, errors.New("no response provided")
	}
	if mask == nil {
		return nil, errors.New("no mask provided")
	}
	lenV := group.PointLen()
	lenSig := lenV + group.ScalarLen()
	VB, err := commitment.MarshalBinary()
	if err != nil {
		return nil, errors.New("marshalling of commitment failed")
	}
	RB, err := response.MarshalBinary()
	if err != nil {
		return nil, errors.New("marshalling of signature failed")
	}
	sig := make([]byte, lenSig+mask.Len())
	copy(sig[:], VB)
	copy(sig[lenV:lenSig], RB)
	copy(sig[lenSig:], mask.mask)
	return sig, nil
}

// Verify checks the given cosignature on the provided message using the list
// of public keys and cosigning policy.
func Verify(group kyber.Group, publics []kyber.Point, message, sig []byte, policy Policy) error {
	if publics == nil {
		return errors.New("no public keys provided")
	}
	if message == nil {
		return errors.New("no message provided")
	}
	if sig == nil {
		return errors.New("no signature provided")
	}
	if policy == nil {
		policy = CompletePolicy{}
	}

	lenCom := group.PointLen()
	VBuff := sig[:lenCom]
	V := group.Point()
	if err := V.UnmarshalBinary(VBuff); err != nil {
		return errors.New("unmarshalling of commitment failed")
	}

	// Unpack the aggregate response
	lenRes := lenCom + group.ScalarLen()
	rBuff := sig[lenCom:lenRes]
	r := group.Scalar().SetBytes(rBuff)

	// Unpack the participation mask and get the aggregate public key
	mask, err := NewMask(group, publics, nil)
	if err != nil {
		return err
	}
	mask.SetMask(sig[lenRes:])
	A := mask.AggregatePublic
	ABuff, err := A.MarshalBinary()
	if err != nil {
		return errors.New("marshalling of aggregate public key failed")
	}

	// Recompute the challenge
	hash := sha512.New()
	hash.Write(VBuff)
	hash.Write(ABuff)
	hash.Write(message)
	buff := hash.Sum(nil)
	k := group.Scalar().SetBytes(buff)

	// k * -aggPublic + s * B = k*-A + s*B
	// from s = k * a + r => s * B = k * a * B + r * B <=> s*B = k*A + r*B
	// <=> s*B + k*-A = r*B
	minusPublic := group.Point().Neg(A)
	kA := group.Point().Mul(k, minusPublic)
	sB := group.Point().Mul(r, nil)
	left := group.Point().Add(kA, sB)

	x, err := left.MarshalBinary()
	if err != nil {
		return err
	}
	y, err := V.MarshalBinary()
	if err != nil {
		return err
	}
	if subtle.ConstantTimeCompare(x, y) == 0 || !policy.Check(mask) {
		return errors.New("invalid signature")
	}
	return nil
}

// Mask represents a cosigning participation bitmask.
type Mask struct {
	mask            []byte
	publics         []kyber.Point
	AggregatePublic kyber.Point
}

// NewMask returns a new participation bitmask for cosigning where all
// cosigners are disabled by default. If a public key is given it verifies that
// it is present in the list of keys and sets the corresponding index in the
// bitmask to 1 (enabled).
func NewMask(group kyber.Group, publics []kyber.Point, myKey kyber.Point) (*Mask, error) {
	m := &Mask{
		publics: publics,
	}
	m.mask = make([]byte, m.Len())
	m.AggregatePublic = group.Point().Null()
	if myKey != nil {
		found := false
		for i, key := range publics {
			if key.Equal(myKey) {
				m.SetBit(i, true)
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

// Mask returns a copy of the participation bitmask.
func (m *Mask) Mask() []byte {
	clone := make([]byte, len(m.mask))
	copy(clone[:], m.mask)
	return clone
}

// Len returns the mask length in bytes.
func (m *Mask) Len() int {
	return (len(m.publics) + 7) >> 3
}

// SetMask sets the participation bitmask according to the given byte slice
// interpreted in little-endian order, i.e., bits 0-7 of byte 0 correspond to
// cosigners 0-7, bits 0-7 of byte 1 correspond to cosigners 8-15, etc.
func (m *Mask) SetMask(mask []byte) error {
	if m.Len() != len(mask) {
		return fmt.Errorf("mismatching mask lengths")
	}
	for i := range m.publics {
		byt := i >> 3
		msk := byte(1) << uint(i&7)
		if ((m.mask[byt] & msk) == 0) && ((mask[byt] & msk) != 0) {
			m.mask[byt] ^= msk // flip bit in mask from 0 to 1
			m.AggregatePublic.Add(m.AggregatePublic, m.publics[i])
		}
		if ((m.mask[byt] & msk) != 0) && ((mask[byt] & msk) == 0) {
			m.mask[byt] ^= msk // flip bit in mask from 1 to 0
			m.AggregatePublic.Sub(m.AggregatePublic, m.publics[i])
		}
	}
	return nil
}

// SetBit enables (enable: true) or disables (enable: false) the bit
// in the participation mask of the given cosigner.
func (m *Mask) SetBit(i int, enable bool) error {
	if i >= len(m.publics) {
		return errors.New("index out of range")
	}
	byt := i >> 3
	msk := byte(1) << uint(i&7)
	if ((m.mask[byt] & msk) == 0) && enable {
		m.mask[byt] ^= msk // flip bit in mask from 0 to 1
		m.AggregatePublic.Add(m.AggregatePublic, m.publics[i])
	}
	if ((m.mask[byt] & msk) != 0) && !enable {
		m.mask[byt] ^= msk // flip bit in mask from 1 to 0
		m.AggregatePublic.Sub(m.AggregatePublic, m.publics[i])
	}
	return nil
}

// CountEnabled returns the number of enabled nodes in the CoSi participation
// mask, i.e., it returns the hamming weight of the mask.
func (m *Mask) CountEnabled() int {
	hw := 0
	for i := range m.publics {
		byt := i >> 3
		msk := byte(1) << uint(i&7)
		if (m.mask[byt] & msk) != 0 {
			hw++
		}
	}
	return hw
}

// CountTotal returns the total number of nodes this CoSi instance knows.
func (m *Mask) CountTotal() int {
	return len(m.publics)
}

// AggregateMasks computes the bitwise OR of the two given participation masks.
func AggregateMasks(a, b []byte) ([]byte, error) {
	if len(a) != len(b) {
		return nil, errors.New("mismatching mask lengths")
	}
	m := make([]byte, len(a))
	for i := range m {
		m[i] = a[i] | b[i]
	}
	return m, nil
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
// least the given threshold number of participants t have cosigned to make a
// collective signature valid.
type ThresholdPolicy struct {
	t int
}

// Check verifies that at least a threshold number of participants have
// contributed to a collective signature.
func (p ThresholdPolicy) Check(m *Mask) bool {
	return m.CountEnabled() >= p.t
}
