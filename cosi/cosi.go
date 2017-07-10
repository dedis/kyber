/*
Package cosi implements the collective signing (CoSi) algorithm as presented in the
paper "Keeping Authorities 'Honest or Bust' with Decentralized Witness
Cosigning" by Ewa Syta et al., see https://arxiv.org/abs/1503.08768.

The CoSi protocol has four phases between a list of participants P having a
protocol leader (index i = 0) and a list of other nodes (index i > 0). The
secret key of node i is denoted by a_i and the public key by A_i = [a_i]G
(where G is the base point of the underlying group and [...] denotes scalar
multiplication). The aggregate public key is given as A = \sum{i ∈ P}(A_i).
The communication can happen via a star topology (with the leader at the
center) or a tree (with the leader at the root). For simplicity we use the star
topology here and refer to the above paper for further details on exception
mechanisms and signature verification policies.

1. Announcement: The leader broadcasts an announcement to the other nodes
optionally including the message M to be signed. Upon receiving an announcement
message, a node starts its commitment phase.

2. Commitment: Each node i picks a random scalar v_i, computes its commitment
V_i = [v_i]G and sends V_i back to the leader. The leader waits until it has
received enough replies (according to some policy) from the other nodes or a
timer has run out. Let P' be the nodes that sent their commitments. Afterwards
the leader computes an aggregate commitment V from all commitments he has
received, i.e., V = \sum{j ∈ P'}(V_j) and starts the challenge phase.

3. Challenge: The leader computes the collective challenge c = H(V || A || M)
using a cryptographic hash function H (here: SHA512) and broadcasts it to the
other nodes along with the message M if it was not sent in phase 1. Upon
receiving a challenge message, a node starts its response phase.

4. Response: Each node i computes its response r_i = v_i - c*a_i and sends it
back to the leader. The leader waits until he has received replies from all
nodes in P' or a timer has run out. If he has not enough replies he aborts.
Finally, the leader computes the aggregate response r = \sum{j ∈ P'}(r_j) and
publishes (V,r) as the signature for the message M.
*/
package cosi

import (
	"crypto/cipher"
	"crypto/sha512"
	"errors"
	"fmt"

	"github.com/dedis/kyber/abstract"
	"github.com/dedis/kyber/random"
	//own "github.com/nikkolasg/learning/crypto/util"
)

// CoSi is the struct that implements one round of a CoSi protocol.
// It's important to only use this struct *once per round*, and if you  try to
// use it twice, it will try to alert you if it can.
// You create a CoSi struct by giving your secret key you wish to pariticipate
// with during the CoSi protocol, and the list of public keys representing the
// list of all co-signer's public keys involved in the round.
// To use CoSi, call three different functions on it which corresponds to the last
// three phases of the protocols:
//  - (Create)Commitment: creates a new secret and its commitment. The output has to
//  be passed up to the parent in the tree.
//  - CreateChallenge: the root creates the challenge from receiving all the
//  commitments. This output must be sent down the tree using Challenge()
//  function.
//  - (Create)Response: creates and possibly aggregates all responses and the
//  output must be sent up into the tree.
// The root can then issue `Signature()` to get the final signature that can be
// verified using `VerifySignature()`.
// To handle missing signers, the signature generation will append a bitmask at
// the end of the signature with each bit index set corresponding to a missing
// cosigner. If you need to specify a missing signer, you can call
// SetMaskBit(i int, enabled bool) which will set the signer i disabled in the
// mask. The index comes from the list of public keys you give when creating the
// CoSi struct. You can also give the full mask directly with SetMask().
type CoSi struct {
	// Suite used
	suite abstract.Suite
	// mask is the mask used to select which signers participated in this round
	// or not. All code regarding the mask is directly inspired from
	// github.com/bford/golang-x-crypto/ed25519/cosi code.
	*mask
	// the message being co-signed
	message []byte
	// V_hat is the aggregated commit (our own + the children's)
	aggregateCommitment abstract.Point
	// challenge holds the challenge for this round
	challenge abstract.Scalar

	// the longterm private key CoSi will use during the response phase.
	// The private key must have its public version in the list of publics keys
	// given to CoSi.
	private abstract.Scalar
	// random is our own secret that we wish to commit during the commitment phase.
	random abstract.Scalar
	// commitment is our own commitment
	commitment abstract.Point
	// response is our own computed response
	response abstract.Scalar
	// aggregateResponses is the aggregated response from the children + our own
	aggregateResponse abstract.Scalar
}

// NewCoSi returns a new CoSi struct given the suite, the longterm secret, and
// the list of public keys. If some signers were not to be participating, you
// have to set the mask using `SetMask` method. By default, all participants are
// designated as participating. If you wish to specify which co-signers are
// participating, use NewCoSiWithMask
func NewCoSi(suite abstract.Suite, private abstract.Scalar, publics []abstract.Point) *CoSi {
	cosi := &CoSi{
		suite:   suite,
		private: private,
	}
	// Start with an all-disabled participation mask, then set it correctly
	cosi.mask = newMask(suite, publics)
	return cosi
}

// CreateCommitment creates the commitment of a random secret generated from the
// given s stream. It returns the message to pass up in the tree. This is
// typically called by the leaves.
func (c *CoSi) CreateCommitment(s cipher.Stream) abstract.Point {
	c.genCommit(s)
	return c.commitment
}

// Commit creates the commitment / secret as in CreateCommitment and it also
// aggregate children commitments from the children's messages.
func (c *CoSi) Commit(s cipher.Stream, subComms []abstract.Point) abstract.Point {
	// generate our own commit
	c.genCommit(s)

	// add our own commitment to the aggregate commitment
	c.aggregateCommitment = c.suite.Point().Add(c.suite.Point().Null(), c.commitment)
	// take the children commitments
	for _, com := range subComms {
		c.aggregateCommitment.Add(c.aggregateCommitment, com)
	}
	return c.aggregateCommitment

}

// CreateChallenge creates the challenge out of the message it has been given.
// This is typically called by Root.
func (c *CoSi) CreateChallenge(msg []byte) (abstract.Scalar, error) {
	// H( Commit || AggPublic || M)
	hash := sha512.New()
	if _, err := c.aggregateCommitment.MarshalTo(hash); err != nil {
		return nil, err
	}
	if _, err := c.mask.Aggregate().MarshalTo(hash); err != nil {
		return nil, err
	}
	hash.Write(msg)
	chalBuff := hash.Sum(nil)
	// reducing the challenge
	c.challenge = c.suite.Scalar().SetBytes(chalBuff)
	c.message = msg
	return c.challenge, nil
}

// Challenge keeps in memory the Challenge from the message.
func (c *CoSi) Challenge(challenge abstract.Scalar) {
	c.challenge = challenge
}

// CreateResponse is called by a leaf to create its own response from the
// challenge + commitment + private key. It returns the response to send up to
// the tree.
func (c *CoSi) CreateResponse() (abstract.Scalar, error) {
	err := c.genResponse()
	return c.response, err
}

// Response generates the response from the commitment, challenge and the
// responses of its children.
func (c *CoSi) Response(responses []abstract.Scalar) (abstract.Scalar, error) {
	//create your own response
	if err := c.genResponse(); err != nil {
		return nil, err
	}
	// Add our own
	c.aggregateResponse = c.suite.Scalar().Set(c.response)
	for _, resp := range responses {
		// add responses of child
		c.aggregateResponse.Add(c.aggregateResponse, resp)
	}
	return c.aggregateResponse, nil
}

// Signature returns a signature using the same format as EdDSA signature
// AggregateCommit || AggregateResponse || Mask
// *NOTE*: Signature() is only intended to be called by the root since only the
// root knows the aggregate response.
func (c *CoSi) Signature() []byte {
	// Sig = C || R || bitmask
	lenC := c.suite.PointLen()
	lenSig := lenC + c.suite.ScalarLen()
	sigC, err := c.aggregateCommitment.MarshalBinary()
	if err != nil {
		panic("Can't marshal Commitment")
	}
	sigR, err := c.aggregateResponse.MarshalBinary()
	if err != nil {
		panic("Can't generate signature !")
	}
	final := make([]byte, lenSig+c.mask.MaskLen())
	copy(final[:], sigC)
	copy(final[lenC:lenSig], sigR)
	copy(final[lenSig:], c.mask.mask)
	return final
}

// VerifyResponses verifies the response this CoSi has against the aggregated
// public key the tree is using. This is callable by any nodes in the tree,
// after it has aggregated its responses. You can enforce verification at each
// level of the tree for faster reactivity.
func (c *CoSi) VerifyResponses(aggregatedPublic abstract.Point) error {
	k := c.challenge

	// k * -aggPublic + s * B = k*-A + s*B
	// from s = k * a + r => s * B = k * a * B + r * B <=> s*B = k*A + r*B
	// <=> s*B + k*-A = r*B
	minusPublic := c.suite.Point().Neg(aggregatedPublic)
	kA := c.suite.Point().Mul(minusPublic, k)
	sB := c.suite.Point().Mul(nil, c.aggregateResponse)
	left := c.suite.Point().Add(kA, sB)

	if !left.Equal(c.aggregateCommitment) {
		return errors.New("recreated commitment is not equal to one given")
	}

	return nil
}

// VerifySignature is the method to call to verify a signature issued by a CoSi
// struct. Publics is the WHOLE list of publics keys, the mask at the end of the
// signature will take care of removing the indivual public keys that did not
// participate
func VerifySignature(suite abstract.Suite, publics []abstract.Point, message, sig []byte) error {
	lenC := suite.PointLen()
	lenSig := lenC + suite.ScalarLen()
	aggCommitBuff := sig[:lenC]
	aggCommit := suite.Point()
	if err := aggCommit.UnmarshalBinary(aggCommitBuff); err != nil {
		panic(err)
	}
	sigBuff := sig[lenC:lenSig]
	sigInt := suite.Scalar().SetBytes(sigBuff)
	maskBuff := sig[lenSig:]
	mask := newMask(suite, publics)
	mask.SetMask(maskBuff)
	aggPublic := mask.Aggregate()
	aggPublicMarshal, err := aggPublic.MarshalBinary()
	if err != nil {
		return err
	}

	hash := sha512.New()
	hash.Write(aggCommitBuff)
	hash.Write(aggPublicMarshal)
	hash.Write(message)
	buff := hash.Sum(nil)
	k := suite.Scalar().SetBytes(buff)

	// k * -aggPublic + s * B = k*-A + s*B
	// from s = k * a + r => s * B = k * a * B + r * B <=> s*B = k*A + r*B
	// <=> s*B + k*-A = r*B
	minusPublic := suite.Point().Neg(aggPublic)
	kA := suite.Point().Mul(minusPublic, k)
	sB := suite.Point().Mul(nil, sigInt)
	left := suite.Point().Add(kA, sB)

	if !left.Equal(aggCommit) {
		return errors.New("Signature invalid")
	}

	return nil
}

// AggregateResponse returns the aggregated response that this cosi has
// accumulated.
func (c *CoSi) AggregateResponse() abstract.Scalar {
	return c.aggregateResponse
}

// GetChallenge returns the challenge that were passed down to this cosi.
func (c *CoSi) GetChallenge() abstract.Scalar {
	return c.challenge
}

// GetCommitment returns the commitment generated by this CoSi (not aggregated).
func (c *CoSi) GetCommitment() abstract.Point {
	return c.commitment
}

// GetResponse returns the individual response generated by this CoSi
func (c *CoSi) GetResponse() abstract.Scalar {
	return c.response
}

// genCommit generates a random scalar vi and computes its individual commit
// Vi = G^vi
func (c *CoSi) genCommit(s cipher.Stream) {
	var stream = s
	if s == nil {
		stream = random.Stream
	}
	c.random = c.suite.Scalar().Pick(stream)
	c.commitment = c.suite.Point().Mul(nil, c.random)
	c.aggregateCommitment = c.commitment
}

// genResponse creates the response
func (c *CoSi) genResponse() error {
	if c.private == nil {
		return errors.New("No private key given in this cosi")
	}
	if c.random == nil {
		return errors.New("No random scalar computed in this cosi")
	}
	if c.challenge == nil {
		return errors.New("No challenge computed in this cosi")
	}

	// resp = random - challenge * privatekey
	// i.e. ri = vi + c * xi
	resp := c.suite.Scalar().Mul(c.private, c.challenge)
	c.response = resp.Add(c.random, resp)
	// no aggregation here
	c.aggregateResponse = c.response
	// paranoid protection: delete the random
	c.random = nil
	return nil
}

// mask represents a cosigning participation bit mask.
type mask struct {
	mask      []byte
	publics   []abstract.Point
	aggPublic abstract.Point
	suite     abstract.Suite
}

// newMask returns a new participation bit mask for cosigning where all cosigners are enabled by default.
func newMask(suite abstract.Suite, publics []abstract.Point) *mask {
	cm := &mask{
		publics: publics,
		suite:   suite,
	}
	cm.mask = make([]byte, cm.MaskLen())
	cm.aggPublic = cm.suite.Point().Null()
	cm.allEnabled()
	return cm

}

// allEnabled sets the participation bit mask to all-1, i.e., to indicate that
// all signers participate.
func (cm *mask) allEnabled() {
	for i := range cm.publics {
		cm.mask[i>>3] |= byte(1) << uint(i&7)
		cm.aggPublic.Add(cm.aggPublic, cm.publics[i])
	}
}

// Mask returns a copy of the byte representation of the participation bit mask.
func (cm *mask) Mask() []byte {
	clone := make([]byte, len(cm.mask))
	copy(clone[:], cm.mask)
	return clone
}

// SetMask sets the participation bit mask according to the given byte slice
// interpreted in little-endian order, i.e., bits 0-7 of byte 0 correspond to
// cosigners 0-7, bits 0-7 of byte 1 correspond to cosigners 8-15, etc.
func (cm *mask) SetMask(mask []byte) error {
	if cm.MaskLen() != len(mask) {
		return fmt.Errorf("Mask length mismatch: %d vs %d", cm.MaskLen(), len(mask))
	}
	for i := range cm.publics {
		byt := i >> 3
		msk := byte(1) << uint(i&7)
		if (cm.mask[byt]&msk) == 0 && ((mask[byt] & msk) != 0) {
			cm.mask[byt] ^= msk // flip bit in mask from 0 to 1
			cm.aggPublic.Add(cm.aggPublic, cm.publics[i])
		}
		if (cm.mask[byt]&msk) != 0 && ((mask[byt] & msk) == 0) {
			cm.mask[byt] ^= msk // flip bit in mask from 1 to 0
			cm.aggPublic.Sub(cm.aggPublic, cm.publics[i])
		}
	}
	return nil
}

// MaskLen returns the mask length in bytes.
func (cm *mask) MaskLen() int {
	return (len(cm.publics) + 7) >> 3
}

// SetMaskBit activates (enable: true) or deactivates (enable: false) the bit
// in the participation mask of the given cosigner.
func (cm *mask) SetMaskBit(signer int, enable bool) {
	if signer > len(cm.publics) {
		panic("SetMaskBit index out of range")
	}
	byt := signer >> 3
	msk := byte(1) << uint(signer&7)
	if enable && ((cm.mask[byt] & msk) == 0) {
		cm.mask[byt] ^= msk // flip bit in mask from 0 to 1
		cm.aggPublic.Add(cm.aggPublic, cm.publics[signer])
	}
	if !enable && ((cm.mask[byt] & msk) != 0) {
		cm.mask[byt] ^= msk // flip bit in mask from 1 to 0
		cm.aggPublic.Sub(cm.aggPublic, cm.publics[signer])
	}
}

// MaskBit returns a boolean value indicating whether the given signer is
// activated (true) or deactivated (false).
func (cm *mask) MaskBit(signer int) bool {
	if signer > len(cm.publics) {
		panic("MaskBit index out of range")
	}
	byt := signer >> 3
	msk := byte(1) << uint(signer&7)
	return (cm.mask[byt] & msk) != 0
}

// MaskHW returns the hamming weight of the CoSi participation mask.
func (cm *mask) MaskHW() int {
	hw := 0
	for i := range cm.publics {
		if cm.MaskBit(i) {
			hw++
		}
	}
	return hw
}

// Aggregate returns the aggregate public key of all *participating* signers.
func (cm *mask) Aggregate() abstract.Point {
	return cm.aggPublic
}
