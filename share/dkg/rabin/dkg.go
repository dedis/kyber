// Package dkg implements the protocol described in
// "Secure Distributed Key Generation for Discrete-Log
// Based Cryptosystems" by R. Gennaro, S. Jarecki, H. Krawczyk, and T. Rabin.
// DKG enables a group of participants to generate a distributed key
// with each participants holding only a share of the key. The key is also
// never computed locally but generated distributively whereas the public part
// of the key is known by every participants.
// The underlying basis for this protocol is the VSS protocol implemented in the
// share/vss package.
//
// The protocol works as follow:
//
//  1. Each participant instantiates a DistKeyShare (DKS) struct.
//  2. Then each participant runs an instance of the VSS protocol:
//     - each participant generates their deals with the method `Deals()` and then
//     sends them to the right recipient.
//     - each participant processes the received deal with `ProcessDeal()` and
//     broadcasts the resulting response.
//     - each participant processes the response with `ProcessResponse()`. If a
//     justification is returned, it must be broadcasted.
//  3. Each participant can check if step 2. is done by calling
//     `Certified()`.Those participants where Certified() returned true, belong to
//     the set of "qualified" participants who will generate the distributed
//     secret. To get the list of qualified participants, use QUAL().
//  4. Each QUAL participant generates their secret commitments calling
//     `SecretCommits()` and broadcasts them to the QUAL set.
//  5. Each QUAL participant processes the received secret commitments using
//     `SecretCommits()`. If there is an error, it can return a commitment complaint
//     (ComplaintCommits) that must be broadcasted to the QUAL set.
//  6. Each QUAL participant receiving a complaint can process it with
//     `ProcessComplaintCommits()` which returns the secret share
//     (ReconstructCommits) given from the malicious participant. This structure
//     must be broadcasted to all the QUAL participant.
//  7. At this point, every QUAL participant can issue the distributed key by
//     calling `DistKeyShare()`.
package dkg

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"

	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/kyber/v3/sign/schnorr"
	"go.dedis.ch/protobuf"

	"go.dedis.ch/kyber/v3/share"
	vss "go.dedis.ch/kyber/v3/share/vss/rabin"
)

// Suite wraps the functionalities needed by the dkg package
type Suite vss.Suite

// DistKeyShare holds the share of a distributed key for a participant.
type DistKeyShare struct {
	// Coefficients of the public polynomial holding the public key
	Commits []kyber.Point
	// Share of the distributed secret
	Share *share.PriShare
}

// Public returns the public key associated with the distributed private key.
func (d *DistKeyShare) Public() kyber.Point {
	return d.Commits[0]
}

// PriShare implements the dss.DistKeyShare interface so either pedersen or
// rabin dkg can be used with dss.
func (d *DistKeyShare) PriShare() *share.PriShare {
	return d.Share
}

// Commitments implements the dss.DistKeyShare interface so either pedersen or
// rabin dkg can be used with dss.
func (d *DistKeyShare) Commitments() []kyber.Point {
	return d.Commits
}

// Deal holds the Deal for one participant as well as the index of the issuing
// Dealer.
//
//	NOTE: Doing that in vss.go would be possible but then the Dealer is always
//	assumed to be a member of the participants. It's only the case here.
type Deal struct {
	// Index of the Dealer in the list of participants
	Index uint32
	// Deal issued for another participant
	Deal *vss.EncryptedDeal
}

// Response holds the Response from another participant as well as the index of
// the target Dealer.
type Response struct {
	// Index of the Dealer for which this response is for
	Index uint32
	// Response issued from another participant
	Response *vss.Response
}

// Justification holds the Justification from a Dealer as well as the index of
// the Dealer in question.
type Justification struct {
	// Index of the Dealer who answered with this Justification
	Index uint32
	// Justification issued from the Dealer
	Justification *vss.Justification
}

// SecretCommits is sent during the distributed public key reconstruction phase,
// basically a Feldman VSS scheme.
type SecretCommits struct {
	// Index of the Dealer in the list of participants
	Index uint32
	// Commitments generated by the Dealer
	Commitments []kyber.Point
	// SessionID generated by the Dealer tied to the Deal
	SessionID []byte
	// Signature from the Dealer
	Signature []byte
}

// ComplaintCommits is sent if the secret commitments revealed by a peer are not
// valid.
type ComplaintCommits struct {
	// Index of the Verifier _issuing_ the ComplaintCommit
	Index uint32
	// DealerIndex being the index of the Dealer who issued the SecretCommits
	DealerIndex uint32
	// Deal that has been given from the Dealer (at DealerIndex) to this node
	// (at Index)
	Deal *vss.Deal
	// Signature made by the verifier
	Signature []byte
}

// ReconstructCommits holds the information given by a participant who reveals
// the deal received from a peer that has received a ComplaintCommits.
type ReconstructCommits struct {
	// Id of the session
	SessionID []byte
	// Index of the verifier who received the deal
	Index uint32
	// DealerIndex is the index of the dealer who issued the Deal
	DealerIndex uint32
	// Share contained in the Deal
	Share *share.PriShare
	// Signature over all over fields generated by the issuing verifier
	Signature []byte
}

// DistKeyGenerator is the struct that runs the DKG protocol.
type DistKeyGenerator struct {
	suite Suite

	index uint32
	long  kyber.Scalar
	pub   kyber.Point

	participants []kyber.Point

	t int

	dealer    *vss.Dealer
	verifiers map[uint32]*vss.Verifier

	// list of commitments to each secret polynomial
	commitments map[uint32]*share.PubPoly

	// Map of deals collected to reconstruct the full polynomial of a dealer.
	// The key is index of the dealer. Once there are enough ReconstructCommits
	// struct, this dkg will re-construct the polynomial and stores it into the
	// list of commitments.
	pendingReconstruct map[uint32][]*ReconstructCommits
	reconstructed      map[uint32]bool
}

// NewDistKeyGenerator returns a DistKeyGenerator out of the suite,
// the longterm secret key, the list of participants, and the
// threshold t parameter. It returns an error if the secret key's
// commitment can't be found in the list of participants.
func NewDistKeyGenerator(suite Suite, longterm kyber.Scalar, participants []kyber.Point, t int) (*DistKeyGenerator, error) {
	pub := suite.Point().Mul(longterm, nil)
	// find our index
	var found bool
	var index uint32
	for i, p := range participants {
		if p.Equal(pub) {
			found = true
			index = uint32(i)
			break
		}
	}
	if !found {
		return nil, errors.New("dkg: own public key not found in list of participants")
	}
	var err error
	// generate our dealer / deal
	ownSec := suite.Scalar().Pick(suite.RandomStream())
	dealer, err := vss.NewDealer(suite, longterm, ownSec, participants, t)
	if err != nil {
		return nil, err
	}

	return &DistKeyGenerator{
		dealer:             dealer,
		verifiers:          make(map[uint32]*vss.Verifier),
		commitments:        make(map[uint32]*share.PubPoly),
		pendingReconstruct: make(map[uint32][]*ReconstructCommits),
		reconstructed:      make(map[uint32]bool),
		t:                  t,
		suite:              suite,
		long:               longterm,
		pub:                pub,
		participants:       participants,
		index:              index,
	}, nil
}

// Deals returns all the deals that must be broadcasted to all
// participants. The deal corresponding to this DKG is already added
// to this DKG and is ommitted from the returned map. To know
// to which participant a deal belongs to, loop over the keys as indices in
// the list of participants:
//
//	for i,dd := range distDeals {
//	   sendTo(participants[i],dd)
//	}
//
// This method panics if it can't process its own deal.
func (d *DistKeyGenerator) Deals() (map[int]*Deal, error) {
	deals, err := d.dealer.EncryptedDeals()
	if err != nil {
		return nil, err
	}
	dd := make(map[int]*Deal)
	for i := range d.participants {
		distd := &Deal{
			Index: d.index,
			Deal:  deals[i],
		}
		if i == int(d.index) {
			if _, ok := d.verifiers[d.index]; ok {
				// already processed our own deal
				continue
			}

			resp, err := d.ProcessDeal(distd)
			if err != nil {
				panic(err)
			} else if !resp.Response.Approved {
				panic("dkg: own deal gave a complaint")
			}

			// If processed own deal correctly, set positive response in this
			// DKG's dealer's own verifier
			d.dealer.UnsafeSetResponseDKG(d.index, true)
			continue
		}
		dd[i] = distd
	}
	return dd, nil
}

// ProcessDeal takes a Deal created by Deals() and stores and verifies it. It
// returns a Response to broadcast to every other participants. It returns an
// error in case the deal has already been stored, or if the deal is incorrect
// (see `vss.Verifier.ProcessEncryptedDeal()`).
func (d *DistKeyGenerator) ProcessDeal(dd *Deal) (*Response, error) {
	// public key of the dealer
	pub, ok := findPub(d.participants, dd.Index)
	if !ok {
		return nil, errors.New("dkg: dist deal out of bounds index")
	}

	if _, ok := d.verifiers[dd.Index]; ok {
		return nil, errors.New("dkg: already received dist deal from same index")
	}

	// verifier receiving the dealer's deal
	ver, err := vss.NewVerifier(d.suite, d.long, pub, d.participants)
	if err != nil {
		return nil, err
	}

	resp, err := ver.ProcessEncryptedDeal(dd.Deal)
	if err != nil {
		return nil, err
	}

	// Set StatusApproval for the verifier that represents the participant
	// that distibuted the Deal
	ver.UnsafeSetResponseDKG(dd.Index, true)

	d.verifiers[dd.Index] = ver
	return &Response{
		Index:    dd.Index,
		Response: resp,
	}, nil
}

// ProcessResponse takes a response from every other peer.  If the response
// designates the deal of another participants than this dkg, this dkg stores it
// and returns nil with a possible error regarding the validity of the response.
// If the response designates a deal this dkg has issued, then the dkg will process
// the response, and returns a justification.
func (d *DistKeyGenerator) ProcessResponse(resp *Response) (*Justification, error) {
	v, ok := d.verifiers[resp.Index]
	if !ok {
		return nil, errors.New("dkg: complaint received but no deal for it")
	}

	if err := v.ProcessResponse(resp.Response); err != nil {
		return nil, err
	}

	if resp.Index != uint32(d.index) {
		return nil, nil
	}

	j, err := d.dealer.ProcessResponse(resp.Response)
	if err != nil {
		return nil, err
	}
	if j == nil {
		return nil, nil
	}
	// a justification for our own deal, are we cheating !?
	if err := v.ProcessJustification(j); err != nil {
		return nil, err
	}

	return &Justification{
		Index:         d.index,
		Justification: j,
	}, nil
}

// ProcessJustification takes a justification and validates it. It returns an
// error in case the justification is wrong.
func (d *DistKeyGenerator) ProcessJustification(j *Justification) error {
	v, ok := d.verifiers[j.Index]
	if !ok {
		return errors.New("dkg: Justification received but no deal for it")
	}
	return v.ProcessJustification(j.Justification)
}

// SetTimeout triggers the timeout on all verifiers, and thus makes sure
// all verifiers have either responded, or have a StatusComplaint response.
func (d *DistKeyGenerator) SetTimeout() {
	for _, v := range d.verifiers {
		v.SetTimeout()
	}
}

// Certified returns true if at least t deals are certified (see
// vss.Verifier.DealCertified()). If the distribution is certified, the protocol
// can continue using d.SecretCommits().
func (d *DistKeyGenerator) Certified() bool {
	return len(d.QUAL()) >= d.t
}

// QUAL returns the index in the list of participants that forms the QUALIFIED
// set as described in the "New-DKG" protocol by Rabin. Basically, it consists
// of all participants that are not disqualified after having  exchanged all
// deals, responses and justification. This is the set that is used to extract
// the distributed public key with SecretCommits() and ProcessSecretCommits().
func (d *DistKeyGenerator) QUAL() []int {
	var good []int
	d.qualIter(func(i uint32, v *vss.Verifier) bool {
		good = append(good, int(i))
		return true
	})
	return good
}

func (d *DistKeyGenerator) isInQUAL(idx uint32) bool {
	var found bool
	d.qualIter(func(i uint32, v *vss.Verifier) bool {
		if i == idx {
			found = true
			return false
		}
		return true
	})
	return found
}

func (d *DistKeyGenerator) qualIter(fn func(idx uint32, v *vss.Verifier) bool) {
	for i, v := range d.verifiers {
		if v.DealCertified() {
			if !fn(i, v) {
				break
			}
		}
	}
}

// SecretCommits returns the commitments of the coefficients of the secret
// polynomials. This secret commits must be broadcasted to every other
// participant and must be processed by ProcessSecretCommits. In this manner,
// the coefficients are revealed through a Feldman VSS scheme.
// This dkg must have its deal certified, otherwise it returns an error. The
// SecretCommits returned is already added to this dkg's list of SecretCommits.
func (d *DistKeyGenerator) SecretCommits() (*SecretCommits, error) {
	if !d.dealer.DealCertified() {
		return nil, errors.New("dkg: can't give SecretCommits if deal not certified")
	}
	sc := &SecretCommits{
		Commitments: d.dealer.Commits(),
		Index:       uint32(d.index),
		SessionID:   d.dealer.SessionID(),
	}
	msg := sc.Hash(d.suite)
	sig, err := schnorr.Sign(d.suite, d.long, msg)
	if err != nil {
		return nil, err
	}
	sc.Signature = sig
	// adding our own commitments
	d.commitments[uint32(d.index)] = share.NewPubPoly(d.suite, d.suite.Point().Base(), sc.Commitments)
	return sc, err
}

// ProcessSecretCommits takes a SecretCommits from every other participant and
// verifies and stores it. It returns an error in case the SecretCommits is
// invalid. In case the SecretCommits are valid, but this dkg can't verify its
// share, it returns a ComplaintCommits that must be broadcasted to every other
// participant. It returns (nil,nil) otherwise.
func (d *DistKeyGenerator) ProcessSecretCommits(sc *SecretCommits) (*ComplaintCommits, error) {
	pub, ok := findPub(d.participants, sc.Index)
	if !ok {
		return nil, errors.New("dkg: secretcommits received with index out of bounds")
	}

	if !d.isInQUAL(sc.Index) {
		return nil, errors.New("dkg: secretcommits from a non QUAL member")
	}

	// mapping verified by isInQUAL
	v := d.verifiers[sc.Index]

	if !bytes.Equal(v.SessionID(), sc.SessionID) {
		return nil, errors.New("dkg: secretcommits received with wrong session id")
	}

	msg := sc.Hash(d.suite)
	if err := schnorr.Verify(d.suite, pub, msg, sc.Signature); err != nil {
		return nil, err
	}

	deal := v.Deal()
	poly := share.NewPubPoly(d.suite, d.suite.Point().Base(), sc.Commitments)
	if !poly.Check(deal.SecShare) {
		cc := &ComplaintCommits{
			Index:       uint32(d.index),
			DealerIndex: sc.Index,
			Deal:        deal,
		}
		var err error
		msg := cc.Hash(d.suite)
		if cc.Signature, err = schnorr.Sign(d.suite, d.long, msg); err != nil {
			return nil, err
		}
		return cc, nil
	}
	// commitments are fine
	d.commitments[sc.Index] = poly
	return nil, nil
}

// ProcessComplaintCommits takes any ComplaintCommits revealed through
// ProcessSecretCommits() from other participants in QUAL. It returns the
// ReconstructCommits message that must be  broadcasted to every other participant
// in QUAL so the polynomial in question can be reconstructed.
func (d *DistKeyGenerator) ProcessComplaintCommits(cc *ComplaintCommits) (*ReconstructCommits, error) {
	issuer, ok := findPub(d.participants, cc.Index)
	if !ok {
		return nil, errors.New("dkg: commitcomplaint with unknown issuer")
	}

	if !d.isInQUAL(cc.Index) {
		return nil, errors.New("dkg: complaintcommit from non-qual member")
	}

	if err := schnorr.Verify(d.suite, issuer, cc.Hash(d.suite), cc.Signature); err != nil {
		return nil, err
	}

	v, ok := d.verifiers[cc.DealerIndex]
	if !ok {
		return nil, errors.New("dkg: commitcomplaint linked to unknown verifier")
	}

	// the verification should pass for the deal, and not with the secret
	// commits. Verification 4) in DKG Rabin's paper.
	if err := v.VerifyDeal(cc.Deal, false); err != nil {
		return nil, fmt.Errorf("dkg: verifying deal: %s", err)
	}

	secretCommits, ok := d.commitments[cc.DealerIndex]
	if !ok {
		return nil, errors.New("dkg: complaint about non received commitments")
	}

	// the secret commits check should fail. Verification 5) in DKG Rabin's
	// paper.
	if secretCommits.Check(cc.Deal.SecShare) {
		return nil, errors.New("dkg: invalid complaint, deal verifying")
	}

	deal := v.Deal()
	if deal == nil {
		return nil, errors.New("dkg: complaint linked to non certified deal")
	}

	delete(d.commitments, cc.DealerIndex)
	rc := &ReconstructCommits{
		SessionID:   cc.Deal.SessionID,
		Index:       d.index,
		DealerIndex: cc.DealerIndex,
		Share:       deal.SecShare,
	}

	msg := rc.Hash(d.suite)
	var err error
	rc.Signature, err = schnorr.Sign(d.suite, d.long, msg)
	if err != nil {
		return nil, err
	}
	d.pendingReconstruct[cc.DealerIndex] = append(d.pendingReconstruct[cc.DealerIndex], rc)
	return rc, nil
}

// ProcessReconstructCommits takes a ReconstructCommits message and stores it
// along any others. If there are enough messages to recover the coefficients of
// the public polynomials of the malicious dealer in question, then the
// polynomial is recovered.
func (d *DistKeyGenerator) ProcessReconstructCommits(rs *ReconstructCommits) error {
	if _, ok := d.reconstructed[rs.DealerIndex]; ok {
		// commitments already reconstructed, no need for other shares
		return nil
	}
	_, ok := d.commitments[rs.DealerIndex]
	if ok {
		return errors.New("dkg: commitments not invalidated by any complaints")
	}

	pub, ok := findPub(d.participants, rs.Index)
	if !ok {
		return errors.New("dkg: reconstruct commits with invalid verifier index")
	}

	msg := rs.Hash(d.suite)
	if err := schnorr.Verify(d.suite, pub, msg, rs.Signature); err != nil {
		return err
	}

	var arr = d.pendingReconstruct[rs.DealerIndex]
	// check if packet is already received or not
	// or if the session ID does not match the others
	for _, r := range arr {
		if r.Index == rs.Index {
			return nil
		}
		if !bytes.Equal(r.SessionID, rs.SessionID) {
			return errors.New("dkg: reconstruct commits invalid session id")
		}
	}
	// add it to list of pending shares
	arr = append(arr, rs)
	d.pendingReconstruct[rs.DealerIndex] = arr
	// check if we can reconstruct commitments
	if len(arr) >= d.t {
		var shares = make([]*share.PriShare, len(arr))
		for i, r := range arr {
			shares[i] = r.Share
		}
		// error only happens when you have less than t shares, but we ensure
		// there are more just before
		pri, _ := share.RecoverPriPoly(d.suite, shares, d.t, len(d.participants))
		d.commitments[rs.DealerIndex] = pri.Commit(d.suite.Point().Base())
		// note it has been reconstructed.
		d.reconstructed[rs.DealerIndex] = true
		delete(d.pendingReconstruct, rs.DealerIndex)
	}
	return nil
}

// Finished returns true if the DKG has operated the protocol correctly and has
// all necessary information to generate the DistKeyShare() by itself. It
// returns false otherwise.
func (d *DistKeyGenerator) Finished() bool {
	var ret = true
	var nb = 0
	d.qualIter(func(idx uint32, v *vss.Verifier) bool {
		nb++
		// ALL QUAL members should have their commitments by now either given or
		// reconstructed.
		if _, ok := d.commitments[idx]; !ok {
			ret = false
			return false
		}
		return true
	})
	return nb >= d.t && ret
}

// DistKeyShare generates the distributed key relative to this receiver
// It throws an error if something is wrong such as not enough deals received.
// The shared secret can be computed when all deals have been sent and
// basically consists of a public point and a share. The public point is the sum
// of all aggregated individual public commits of each individual secrets.
// the share is evaluated from the global Private Polynomial, basically SUM of
// fj(i) for a receiver i.
func (d *DistKeyGenerator) DistKeyShare() (*DistKeyShare, error) {
	if !d.Certified() {
		return nil, errors.New("dkg: distributed key not certified")
	}

	sh := d.suite.Scalar().Zero()
	var pub *share.PubPoly
	var err error

	d.qualIter(func(i uint32, v *vss.Verifier) bool {
		// share of dist. secret = sum of all share received.
		s := v.Deal().SecShare.V
		sh = sh.Add(sh, s)
		// Dist. public key = sum of all revealed commitments
		poly, ok := d.commitments[i]
		if !ok {
			err = fmt.Errorf("dkg: protocol not finished: %d commitments missing", i)
			return false
		}
		if pub == nil {
			// first polynomial we see (instead of generating n empty commits)
			pub = poly
			return true
		}
		pub, err = pub.Add(poly)
		return err == nil
	})

	if err != nil {
		return nil, err
	}
	_, commits := pub.Info()

	return &DistKeyShare{
		Commits: commits,
		Share: &share.PriShare{
			I: int64(d.index),
			V: sh,
		},
	}, nil
}

// Hash returns the hash value of this struct used in the signature process.
func (sc *SecretCommits) Hash(s Suite) []byte {
	h := s.Hash()
	_, _ = h.Write([]byte("secretcommits"))
	_ = binary.Write(h, binary.LittleEndian, sc.Index)
	for _, p := range sc.Commitments {
		_, _ = p.MarshalTo(h)
	}
	return h.Sum(nil)
}

// Hash returns the hash value of this struct used in the signature process.
func (cc *ComplaintCommits) Hash(s Suite) []byte {
	h := s.Hash()
	_, _ = h.Write([]byte("commitcomplaint"))
	_ = binary.Write(h, binary.LittleEndian, cc.Index)
	_ = binary.Write(h, binary.LittleEndian, cc.DealerIndex)
	buff, _ := protobuf.Encode(cc.Deal)
	_, _ = h.Write(buff)
	return h.Sum(nil)
}

// Hash returns the hash value of this struct used in the signature process.
func (rc *ReconstructCommits) Hash(s Suite) []byte {
	h := s.Hash()
	_, _ = h.Write([]byte("reconstructcommits"))
	_ = binary.Write(h, binary.LittleEndian, rc.Index)
	_ = binary.Write(h, binary.LittleEndian, rc.DealerIndex)
	_, _ = h.Write(rc.Share.Hash(s))
	return h.Sum(nil)
}

func findPub(list []kyber.Point, i uint32) (kyber.Point, bool) {
	if i >= uint32(len(list)) {
		return nil, false
	}
	return list[i], true
}
