/*
Package cosi is the Collective Signing implementation according to the paper of
Bryan Ford: http://arxiv.org/pdf/1503.08768v1.pdf .

Stages of CoSi

The CoSi-protocol has 4 stages:

1. Announcement: The leader multicasts an announcement
of the start of this round down through the spanning tree,
optionally including the statement S to be signed.

2. Commitment: Each node i picks a random secret vi and
computes its individual commit Vi = Gvi . In a bottom-up
process, each node i waits for an aggregate commit Vˆj from
each immediate child j, if any. Node i then computes its
own aggregate commit Vˆi = Vi \prod{j ∈ Cj}{Vˆj}, where Ci is the
set of i’s immediate children. Finally, i passes Vi up to its
parent, unless i is the leader (node 0).

3. Challenge: The leader computes a collective challenge
c = H( Aggregate Commit ∥ Aggregate Public key || Message ),
then multicasts c down through the tree, along
with the statement S to be signed if it was not already
announced in phase 1.

4. Response: In a final bottom-up phase, each node i waits
to receive a partial aggregate response rˆj from each of
its immediate children j ∈ Ci. Node i now computes its
individual response ri = vi + cxi, and its partial aggregate
response rˆi = ri + \sum{j ∈ Cj}{rˆj} . Node i finally passes rˆi
up to its parent, unless i is the root.
*/
package cosi

import (
	cryptoRand "crypto/rand"
	"crypto/sha512"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/dedis/crypto/abstract"
	//own "github.com/nikkolasg/learning/crypto/util"
)

// Cosi is the struct that implements the basic cosi.
type Cosi struct {
	// Suite used
	suite abstract.Suite
	// publics is the list of public keys used for signing
	publics []abstract.Point
	// mask is the mask used to select which signers participated in this round
	// or not. All code regarding the mask is directly inspired from
	// github.com/bford/golang-x-crypto/ed25519/cosi code.
	mask *CosiMask
	// the longterm private key we use during the rounds
	private abstract.Secret
	// the message being co-signed
	message []byte
	// timestamp of when the announcement is done (i.e. timestamp of the four
	// phases)
	timestamp int64
	// random is our own secret that we wish to commit during the commitment phase.
	random abstract.Secret
	// commitment is our own commitment
	commitment abstract.Point
	// V_hat is the aggregated commit (our own + the children's)
	aggregateCommitment abstract.Point
	// globalComitment is the global commit of all participants
	//passed down in the challenge phase
	globalCommitment abstract.Point
	// challenge holds the challenge for this round
	challenge abstract.Secret
	// response is our own computed response
	response abstract.Secret
	// aggregateResponses is the aggregated response from the children + our own
	aggregateResponse abstract.Secret
}

// NewCosi returns a new Cosi struct given the suite, the longterm secret, and
// the list of public keys. If some signers were not to be participating, you
// have to set the mask using `SetMask` method. By default, all participants are
// designated as participating.
func NewCosi(suite abstract.Suite, private abstract.Secret, publics []abstract.Point) *Cosi {
	cos := &Cosi{
		suite:   suite,
		private: private,
		publics: publics,
	}
	// Start with an all-disabled participation mask, then set it correctly
	cos.mask = NewCosiMask(suite, publics)
	return cos
}

// Announcement holds only the timestamp for that round
type Announcement struct {
	Timestamp int64
}

// Commitment sends it's own commit Vi and the aggregate children's
// commit V^i
type Commitment struct {
	Commitment     abstract.Point
	ChildrenCommit abstract.Point
}

// Challenge is the Hash of Commit || Publics || Msg
// Commit is the aggregated global commit
type Challenge struct {
	Challenge        abstract.Secret
	GlobalCommitment abstract.Point
}

// Response holds the actual node's response ri and the
// aggregate response r^i
type Response struct {
	Response     abstract.Secret
	ChildrenResp abstract.Secret
}

// CreateAnnouncement creates an Announcement message with the timestamp set
// to the current time.
func (c *Cosi) CreateAnnouncement() *Announcement {
	now := time.Now().Unix()
	c.timestamp = now
	return &Announcement{now}
}

// Announce stores the timestamp and relays the message.
func (c *Cosi) Announce(in *Announcement) *Announcement {
	c.timestamp = in.Timestamp
	return in
}

// CreateCommitment creates the commitment out of the random secret and returns
// the message to pass up in the tree. This is typically called by the leaves.
func (c *Cosi) CreateCommitment(r io.Reader) *Commitment {
	c.genCommit(r)
	return &Commitment{
		Commitment: c.commitment,
	}
}

// Commit creates the commitment / secret + aggregate children commitments from
// the children's messages.
func (c *Cosi) Commit(r io.Reader, comms []*Commitment) *Commitment {
	// generate our own commit
	c.genCommit(r)

	// take the children commitment
	childVHat := c.suite.Point().Null()
	for _, com := range comms {
		// Add commitment of one child
		childVHat = childVHat.Add(childVHat, com.Commitment)
		// add commitment of it's children if there is one (i.e. if it is not a
		// leaf)
		if com.ChildrenCommit != nil {
			childVHat = childVHat.Add(childVHat, com.ChildrenCommit)
		}
	}
	// add our own commitment to the global V_hat
	c.aggregateCommitment = c.suite.Point().Add(childVHat, c.commitment)
	return &Commitment{
		ChildrenCommit: childVHat,
		Commitment:     c.commitment,
	}

}

// CreateChallenge creates the challenge out of the message it has been given.
// This is typically called by Root.
func (c *Cosi) CreateChallenge(msg []byte) (*Challenge, error) {
	// H( Commit || AggPublic || M)
	hash := sha512.New()

	pb, err := c.aggregateCommitment.MarshalBinary()
	if err != nil {
		return nil, err
	}
	hash.Write(pb)
	pb, err = c.mask.Aggregate().MarshalBinary()
	if err != nil {
		return nil, err
	}
	hash.Write(pb)
	hash.Write(msg)
	chalBuff := hash.Sum(nil)
	// reducing the challenge
	c.challenge = sliceToSecret(c.suite, chalBuff)
	c.message = msg
	/*fmt.Println("Abstract Challenge aggCommit = ", own.Abstract2Hex(c.aggregateCommitment))*/
	//fmt.Println("Abstract Challenge aggPublic = ", own.Abstract2Hex(c.mask.Aggregate()))
	//fmt.Println("Abstract Challenge msg = ", hex.EncodeToString(msg))
	/*fmt.Println("Abstract Challenge k = ", own.Abstract2Hex(c.challenge))*/
	return &Challenge{
		Challenge:        c.challenge,
		GlobalCommitment: c.aggregateCommitment,
	}, nil
}

// Challenge keeps in memory the Challenge from the message.
func (c *Cosi) Challenge(ch *Challenge) *Challenge {
	c.challenge = ch.Challenge
	c.globalCommitment = ch.GlobalCommitment
	return ch
}

// CreateResponse is called by a leaf to create its own response from the
// challenge + commitment + private key. It returns the response to send up to
// the tree.
func (c *Cosi) CreateResponse() (*Response, error) {
	err := c.genResponse()
	return &Response{Response: c.response}, err
}

// Response generates the response from the commitment, challenge and the
// responses of its children.
func (c *Cosi) Response(responses []*Response) (*Response, error) {
	// //create your own response
	if err := c.genResponse(); err != nil {
		return nil, err
	}
	aggregateResponse := c.suite.Secret().Zero()
	for _, resp := range responses {
		// add responses of child
		aggregateResponse = aggregateResponse.Add(aggregateResponse, resp.Response)
		// add responses of it's children if there is one (i.e. if it is not a
		// leaf)
		if resp.ChildrenResp != nil {
			aggregateResponse = aggregateResponse.Add(aggregateResponse, resp.ChildrenResp)
		}
	}
	// Add our own
	c.aggregateResponse = c.suite.Secret().Add(aggregateResponse, c.response)
	return &Response{
		Response:     c.response,
		ChildrenResp: aggregateResponse,
	}, nil
}

// Signature returns a signature in the like the EdDSA signature format plus the
// bitmask at the end.
// Sig = AggCommit || AggResponse || bitmask
func (c *Cosi) Signature() []byte {
	// Sig = R || S || bitmask
	sigS := secretToSlice(c.aggregateResponse)
	/*fmt.Println("Abstract Signature() aggResponse = ", own.Abstract2Hex(c.aggregateResponse))*/
	/*fmt.Println("Abstract Signature() sigS = ", hex.EncodeToString(sigS))*/
	//sigS := c.aggregateResponse.(*nist.Int).LittleEndian(32, 32)
	sigR, err := c.aggregateCommitment.MarshalBinary()
	if err != nil {
		panic("Can't generate signature !")
	}
	final := make([]byte, 64+c.mask.MaskLen())
	copy(final[:], sigR)
	copy(final[32:64], sigS)
	copy(final[64:], c.mask.mask)
	return final
}

// GetAggregateResponse returns the aggregated response that this cosi has
// accumulated.
func (c *Cosi) GetAggregateResponse() abstract.Secret {
	return c.aggregateResponse
}

// GetChallenge returns the challenge that were passed down to this cosi.
func (c *Cosi) GetChallenge() abstract.Secret {
	return c.challenge
}

// GetCommitment returns the commitment generated by this CoSi (not aggregated).
func (c *Cosi) GetCommitment() abstract.Point {
	return c.commitment
}

// VerifyResponses verifies the response this CoSi has against the aggregated
// public key the tree is using.
// Reconstruct the AggCommit
func (c *Cosi) VerifyResponses(aggregatedPublic abstract.Point) error {
	/*var aggCommitMarshal []byte*/
	//var aggPublicMarshal []byte
	//var err error
	//if aggCommitMarshal, err = c.mask.Aggregate().MarshalBinary(); err != nil {
	//return err
	//} else if aggPublicMarshal, err = c.globalCommitment.MarshalBinary(); err != nil {
	//return err
	/*}*/
	k := c.challenge

	// k * -aggPublic + s * B = k*-A + s*B
	// from s = k * a + r => s * B = k * a * B + r * B <=> s*B = k*A + r*B
	// <=> s*B + k*-A = r*B
	minusPublic := c.suite.Point().Neg(aggregatedPublic)
	kA := c.suite.Point().Mul(minusPublic, k)
	sB := c.suite.Point().Mul(nil, c.aggregateResponse)
	left := c.suite.Point().Add(kA, sB)

	/*fmt.Println("Abstract VerifyResponse Global AggCommit = ", hex.EncodeToString(aggCommitMarshal))*/
	//fmt.Println("Abstract VerifyResponse Global AggPublic = ", hex.EncodeToString(aggPublicMarshal))
	//fmt.Println("Abstract VerifyResponse SubTree AggPublic = ", own.Abstract2Hex(aggregatedPublic))
	//fmt.Println("Abstract VerifyResponse -(AggPublic) = ", own.Abstract2Hex(minusPublic))
	//fmt.Println("Abstract VerifyResponse Message = ", hex.EncodeToString(c.message))
	//fmt.Println("Abstract VerifyResponse k = ", own.Abstract2Hex(k))
	//fmt.Println("Abstract VerifyResponse sig(S) = ", own.Abstract2Hex(left))

	if !left.Equal(c.aggregateCommitment) {
		return errors.New("recreated commitment is not equal to one given")
	}

	return nil
}

// VerifySignature is the method to call to verify a signature issued by a Cosi
// struct. Publics is the WHOLE list of publics keys, the mask at the end of the
// signature will take care of removing the indivual public keys that did not
// participate
func VerifySignature(suite abstract.Suite, publics []abstract.Point, message, sig []byte) error {
	aggCommitBuff := sig[:32]
	aggCommit := suite.Point()
	if err := aggCommit.UnmarshalBinary(aggCommitBuff); err != nil {
		panic(err)
	}
	sigBuff := sig[32:64]
	sigInt := sliceToSecret(suite, sigBuff)
	maskBuff := sig[64:]
	mask := NewCosiMask(suite, publics)
	mask.Set(maskBuff)
	aggPublic := mask.Aggregate()
	aggPublicMarshal, err := aggPublic.MarshalBinary()
	if err != nil {
		return err
	}

	hash := sha512.New()
	hash.Write(aggCommitBuff)
	hash.Write(aggPublicMarshal)
	hash.Write(message)
	kBuff := hash.Sum(nil)
	k := sliceToSecret(suite, kBuff)

	// k * -aggPublic + s * B = k*-A + s*B
	// from s = k * a + r => s * B = k * a * B + r * B <=> s*B = k*A + r*B
	// <=> s*B + k*-A = r*B
	minusPublic := suite.Point().Neg(aggPublic)
	kA := suite.Point().Mul(minusPublic, k)
	sB := suite.Point().Mul(nil, sigInt)
	left := suite.Point().Add(kA, sB)

	/*fmt.Println("Abstract Verify AggCommit = ", hex.EncodeToString(aggCommitBuff))*/
	//fmt.Println("Abstract Verify AggPublic = ", hex.EncodeToString(aggPublicMarshal))
	//fmt.Println("Abstract Verify -(AggPublic) = ", own.Abstract2Hex(minusPublic))
	//fmt.Println("Abstract Verify Message = ", hex.EncodeToString(message))
	//fmt.Println("Abstract Verify k = ", own.Abstract2Hex(k))
	//fmt.Println("Abstract Verify sig(S) = ", hex.EncodeToString(sigBuff))
	//fmt.Println("Abstract Verify sig(S)int = ", own.Abstract2Hex(sigInt))
	//fmt.Println("Abstract Verify sig(R) = ", hex.EncodeToString(aggCommitBuff))
	//fmt.Println("Abstract Verify checkR = ", own.Abstract2Hex(left))

	if !left.Equal(aggCommit) {
		return errors.New("Signature invalid")
	}

	return nil
}

// genCommit generates a random secret vi and computes it's individual commit
// Vi = G^vi
func (c *Cosi) genCommit(r io.Reader) {
	var reader = r
	if r == nil {
		reader = cryptoRand.Reader
	}
	var randomFull [64]byte
	if _, err := io.ReadFull(reader, randomFull[:]); err != nil {
		panic(err)
	}
	c.random = sliceToSecret(c.suite, randomFull[:])
	c.commitment = c.suite.Point().Mul(nil, c.random)
	c.aggregateCommitment = c.commitment
}

// genResponse creates the response
func (c *Cosi) genResponse() error {
	if c.private == nil {
		return errors.New("No private key given in this cosi")
	}
	if c.random == nil {
		return errors.New("No random secret computed in this cosi")
	}
	if c.challenge == nil {
		return errors.New("No challenge computed in this cosi")
	}

	// hash the private key
	hash := sha512.New()
	privKeyBuff := secretToSlice(c.private)
	//privKeyBuff := c.private.(*nist.Int).LittleEndian(32, 32)

	hash.Write(privKeyBuff)
	h := hash.Sum(nil)

	// prune it up
	expandedPrivKey := h[0:32]
	expandedPrivKey[0] &= 248
	expandedPrivKey[31] &= 127
	expandedPrivKey[31] |= 64
	expandedPrivKeyInt := sliceToSecret(c.suite, expandedPrivKey)

	// resp = random - challenge * privatekey
	// i.e. ri = vi + c * xi
	resp := c.suite.Secret().Mul(expandedPrivKeyInt, c.challenge)
	c.response = resp.Add(c.random, resp)
	// no aggregation here
	c.aggregateResponse = c.response
	return nil
}

// CosiMask holds the mask utilities
type CosiMask struct {
	mask      []byte
	publics   []abstract.Point
	aggPublic abstract.Point
	suite     abstract.Suite
}

// NewCosiMask returns a new mask to use with the cosigning with all cosigners enabled
func NewCosiMask(suite abstract.Suite, publics []abstract.Point) *CosiMask {
	// Start with an all-disabled participation mask, then set it correctly
	cm := &CosiMask{
		publics: publics,
		suite:   suite,
	}
	cm.mask = make([]byte, cm.MaskLen()) //(len(publics)+7)>>3)
	cm.aggPublic = cm.suite.Point().Null()
	cm.AllEnabled()
	return cm

}

func (cm *CosiMask) AllEnabled() {
	for i := range cm.mask {
		cm.mask[i] = 0xff // all disabled
	}
	cm.Set(make([]byte, len(cm.mask)))
}

// SetMask sets the entire participation bitmask according to the provided
// packed byte-slice interpreted in little-endian byte-order.
// That is, bits 0-7 of the first byte correspond to cosigners 0-7,
// bits 0-7 of the next byte correspond to cosigners 8-15, etc.
// Each bit is set to indicate the corresponding cosigner is disabled,
// or cleared to indicate the cosigner is enabled.
//
// If the mask provided is too short (or nil),
// SetMask conservatively interprets the bits of the missing bytes
// to be 0, or Enabled.
func (cm *CosiMask) Set(mask []byte) error {
	if cm.MaskLen() != len(mask) {
		err := fmt.Errorf("CosiMask.MaskLen() is %d but is given %d bytes)", cm.MaskLen(), len(mask))
		return err
	}
	masklen := len(mask)
	for i := range cm.publics {
		byt := i >> 3
		bit := byte(1) << uint(i&7)
		if (byt < masklen) && (mask[byt]&bit != 0) {
			// Participant i disabled in new mask.
			if cm.mask[byt]&bit == 0 {
				cm.mask[byt] |= bit // disable it
				cm.aggPublic.Sub(cm.aggPublic, cm.publics[i])
			}
		} else {
			// Participant i enabled in new mask.
			if cm.mask[byt]&bit != 0 {
				cm.mask[byt] &^= bit // enable it
				cm.aggPublic.Add(cm.aggPublic, cm.publics[i])
			}
		}
	}
	return nil
}

// MaskLen returns the length in bytes
// of a complete disable-mask for this cosigner list.
func (cm *CosiMask) MaskLen() int {
	return (len(cm.publics) + 7) >> 3
}

// SetMaskBit enables or disables the mask bit for an individual cosigner.
func (cm *CosiMask) SetMaskBit(signer int, enabled bool) {
	if signer > len(cm.publics) {
		panic("SetMaskBit range out of index")
	}
	byt := signer >> 3
	bit := byte(1) << uint(signer&7)
	if !enabled {
		if cm.mask[byt]&bit == 0 { // was enabled
			cm.mask[byt] |= bit // disable it
			cm.aggPublic.Sub(cm.aggPublic, cm.publics[signer])
		}
	} else { // enable
		if cm.mask[byt]&bit != 0 { // was disabled
			cm.mask[byt] &^= bit
			cm.aggPublic.Add(cm.aggPublic, cm.publics[signer])
		}
	}
}

// MaskBit returns a boolean value indicating whether
// the indicated signer is enabled (true) or disabled (false)
func (cm *CosiMask) MaskBit(signer int) bool {
	if signer > len(cm.publics) {
		panic("MaskBit given index out of range")
	}
	byt := signer >> 3
	bit := byte(1) << uint(signer&7)
	return (cm.mask[byt] & bit) != 0
}

func (cm *CosiMask) MarshalBinary() ([]byte, error) {
	clone := make([]byte, len(cm.mask))
	copy(clone[:], cm.mask)
	return clone, nil
}

func (cm *CosiMask) UnmarshalBinary(buff []byte) error {
	return cm.Set(buff)
}

func (cm *CosiMask) Aggregate() abstract.Point {
	return cm.aggPublic
}
