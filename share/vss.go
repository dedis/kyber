// vss.go implements the verifiable secret sharing scheme by Pedersen from
// "Non-interactive and information-theoretic secure verifiable secret
// sharing", in Crypto ’91, pages 129–140, 1991
package share

import (
	"bytes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/dedis/crypto/abstract"
	"github.com/dedis/crypto/sign"
)

// Dealer is responsible for creating the shares, distribute them and reply to
// any Complaints.
type Dealer struct {
	suite abstract.Suite

	reader cipher.Stream
	long   abstract.Scalar

	secret abstract.Scalar

	verifiers []abstract.Point
	// threshold of shares that is needed to reconstruct the secret
	t int
	// sessionID is a unique identifier for the whole session of the scheme
	sessionID []byte
	// second base derived from the list of verifiers H ( Verifiers )
	h abstract.Point

	// list of deals this Dealer has generated
	deals []*Deal
	// commitments of (f + g) polynomial
	commitments []abstract.Point
	*aggregator
}

// Deal is sent by the Dealer to each participants. It contains the encrypted
// share for a specific Verifier.
type Deal struct {
	SessionID   []byte
	SecShare    *PriShare
	RndShare    *PriShare
	T           uint32
	Commitments []abstract.Point
}

// NewDealer returns a Dealer capable of leading the secret sharing scheme. It
// does not have to be trusted by other Verifiers. The security parameter t is
// the number of shares required to reconstruct the secret. It must be between
// (len(verifiers) + 1)/2 <= t <= len(verifiers).
func NewDealer(suite abstract.Suite, longterm, secret abstract.Scalar, verifiers []abstract.Point, r cipher.Stream, t int) (*Dealer, error) {
	d := &Dealer{
		suite:     suite,
		long:      longterm,
		secret:    secret,
		verifiers: verifiers,
		reader:    r,
	}
	if !validT(t, verifiers) {
		return nil, fmt.Errorf("dealer: t %d invalid.", t)
	}

	d.t = t

	d.h = deriveH(d.suite, d.verifiers)
	f := NewPriPoly(d.suite, d.t, d.secret, d.reader)
	g := NewPriPoly(d.suite, d.t, nil, d.reader)
	pub := d.suite.Point().Mul(nil, d.long)

	// F = coeff * B
	F := f.Commit(d.suite.Point().Base())
	// G = coeff * H
	G := g.Commit(d.h)

	C, err := F.Add(G)
	if err != nil {
		return nil, err
	}
	_, d.commitments = C.Info()

	d.sessionID, err = sessionID(pub, d.verifiers, d.commitments, d.t)
	if err != nil {
		return nil, err
	}

	d.aggregator = newAggregator(d.suite, d.verifiers, d.commitments, d.t, d.sessionID)
	// C = F + G
	d.deals = make([]*Deal, len(d.verifiers))
	for i := range d.verifiers {
		fi := f.Eval(i)
		gi := g.Eval(i)
		d.deals[i] = &Deal{
			SessionID:   d.sessionID,
			SecShare:    fi,
			RndShare:    gi,
			Commitments: d.commitments,
			T:           uint32(d.t),
		}
	}
	return d, nil
}

// Deals returns a list of deal for each verifiers.
func (d *Dealer) Deals() []*Deal {
	var out = make([]*Deal, len(d.deals))
	copy(out, d.deals)
	return out
}

// ReceiveComplaint analyzes the given complaint. If it's a valid complaint,
// then it returns a DealerResponse. This response must be broadcasted to every
// participants. If it's an invalid complaint, it returns an error about the
// complaints. The verifiers will also ignore an invalid Complaint.
func (d *Dealer) ReceiveComplaint(c *Complaint) (*DealerResponse, error) {
	if err := d.verifyComplaint(c, true); err != nil {
		return nil, err
	}
	// index is guaranteed to be found because verifyComplaint does the check
	i, _ := findIndex(d.verifiers, c.Public)
	return &DealerResponse{
		Deal:      d.deals[i],
		Complaint: c,
	}, nil
}

// ReceiveApproval looks if the approval is legitimate and stores it. If the
// approval is not legitimate or has already been received, it returns an error.
// To knoew whether participants approved the sharing, call `d.EnoughApproval`
// and if true, `d.DealCertified`.
func (d *Dealer) ReceiveApproval(a *Approval) error {
	return d.verifyApproval(a)
}

// Verifier receives a Deal from a Dealer, can reply by a Complaint, and can
// collaborate with other Verifiers to reconstruct a secret.
type Verifier struct {
	suite abstract.Suite

	long abstract.Scalar
	pub  abstract.Point

	dealer abstract.Point

	index     int
	verifiers []abstract.Point

	h abstract.Point

	commitPoly *PubPoly

	fi *PriShare
	gi *PriShare

	*aggregator

	dealerBad bool
}

// NewVerifier returns a Verifier out of:
// - its longterm secret key
// - the longterm dealer public key
// - the list of public key of verifiers. The list MUST include the public key
// of this Verifier also.
// The security parameter t of the secret sharing scheme is automatically set to
// a default safe value. If a different t value is required, it is possible to set
// it with `verifier.SetT()`.
func NewVerifier(suite abstract.Suite, longterm abstract.Scalar, dealerKey abstract.Point,
	verifiers []abstract.Point) (*Verifier, error) {
	v := &Verifier{
		suite:     suite,
		long:      longterm,
		dealer:    dealerKey,
		verifiers: verifiers,
	}
	v.pub = v.suite.Point().Mul(nil, v.long)
	var ok bool
	if v.index, ok = findIndex(verifiers, v.pub); !ok {
		return nil, errors.New("verifier: not in the list of verifiers")
	}
	v.h = deriveH(suite, verifiers)
	return v, nil
}

// ReceiveDeal takes a Deal, tries to decrypt it and see if it is correct or
// not. In case the Deal is correct, an Approval is returned and must be
// broadcasted to every participants including the Dealer. In case the Deal
// is not correct, it returns a Complaint which must be broadcasted to every
// participants including the Dealer. ReceiveDeal returns an error in any case
// to let the user know what went wrong.
// XXX API question: return value.For the moment, the default is to let the user
// know everything that is wrong through the error.
func (v *Verifier) ReceiveDeal(d *Deal) (*Approval, *Complaint, error) {
	if d.SecShare.I != v.index {
		return nil, nil, errors.New("verifier: wrong index from deal")
	}

	if !validT(int(d.T), v.verifiers) {
		return nil, nil, errors.New("verifier: invalid t received in Deal")
	}
	t := int(d.T)

	sid, err := sessionID(v.dealer, v.verifiers, d.Commitments, t)
	if err != nil {
		return nil, nil, err
	} else if !bytes.Equal(sid, d.SessionID) {
		return nil, nil, errors.New("verifier: invalid session id in Deal")
	}

	if v.aggregator == nil {
		v.aggregator = newAggregator(v.suite, v.verifiers, d.Commitments, t, d.SessionID)
	}

	sig, err := sign.Schnorr(v.suite, v.long, sid)
	if err := v.verifyDeal(d, true); err != nil {
		if err == errDealAlreadyReceived {
			return nil, nil, err
		}
		complaint := &Complaint{
			Public:    v.pub,
			Deal:      d,
			Signature: sig,
		}
		return nil, complaint, err
	}
	approval := &Approval{
		Public:    v.pub,
		Signature: sig,
	}
	return approval, nil, nil
}

// ReceiveComplaints takes a Complaint and stores it if the Complaint is valid.
// If the verifier already saw a Complaint from the same origin, it returns an error.
// If the Complaint is not valid, it returns an error. That does NOT mean the
// Deal is not good, but rather only this Complaint is not valid and should not
// be treated.  To know whether the deal is good, call first v.EnoughApproval(),
// and if true, call v.IsDealGood().
func (v *Verifier) ReceiveComplaint(c *Complaint) error {
	return v.verifyComplaint(c, true)
}

// ReceiveDealerResponse takes a DealerResponse and returns an error if
// something went wrong during the verification. If it is the case, that
// probably means the Dealer is acting maliciously. In order to be sure, call
// v.EnoughApprovals() and if true, v.IsDealGood().
// NOTE: it does *not* verify the complaint associated with since it is supposed
// to already have received it.
func (v *Verifier) ReceiveDealerResponse(dr *DealerResponse) error {
	pub := dr.Complaint.Public
	if _, ok := v.aggregator.complaints[pub.String()]; !ok {
		return errors.New("verifier: no complaints received for this response")
	}

	if err := v.verifyDeal(dr.Deal, false); err != nil {
		// if one response is bad, flag the dealer as malicious
		v.dealerBad = true
		return err
	}
	return nil
}

func (v *Verifier) ReceiveApproval(ap *Approval) error {
	return v.verifyApproval(ap)
}

func (v *Verifier) DealCertified() bool {
	return v.aggregator.DealCertified() && !v.dealerBad
}

// Complaint is a message that must be broadcasted to every verifiers when
// a verifier receives an invalid Deal.
type Complaint struct {
	Public abstract.Point
	Deal   *Deal
	// Signature over the msg
	// H(Index || deal.MarshalBinary() || verifiers)
	Signature []byte
}

// DealerResponse is a message that is broadcasted by the Dealer in response to
// a Complaint. It contains the original Complaint as well as the shares
// distributed to the complainer.
type DealerResponse struct {
	*Complaint
	*Deal
}

// Approval is a message that is sent if a verifier approves the Deal he
// received from the Dealer.
type Approval struct {
	Public abstract.Point
	// Signature over the msg
	// H(Index || commitments || verifiers)
	Signature []byte
}

type aggregator struct {
	suite     abstract.Suite
	verifiers []abstract.Point
	commits   []abstract.Point

	complaints map[string]*Complaint
	approvals  map[string]*Approval
	sid        []byte
	deal       *Deal
	t          int
}

func newAggregator(suite abstract.Suite, verifiers, commitments []abstract.Point, t int, sid []byte) *aggregator {
	agg := &aggregator{
		suite:      suite,
		verifiers:  verifiers,
		commits:    commitments,
		t:          t,
		sid:        sid,
		complaints: make(map[string]*Complaint),
		approvals:  make(map[string]*Approval),
	}
	return agg

}

var errDealAlreadyReceived = errors.New("deal: already received a deal")

func (a *aggregator) verifyDeal(d *Deal, inclusion bool) error {
	if a.deal != nil && inclusion {
		return errDealAlreadyReceived

	}
	if a.deal == nil {
		a.commits = d.Commitments
		a.sid = d.SessionID
		a.deal = d
	}

	if !bytes.Equal(a.sid, d.SessionID) {
		return errors.New("deal: sessionID is different from locally computed")
	}

	fi := d.SecShare
	gi := d.RndShare
	if fi.I != gi.I {
		return errors.New("deal: not the same index for f and g share")
	} else if fi.I < 0 || fi.I >= len(a.verifiers) {
		return errors.New("deal: index out of bounds")
	}
	// compute fi * G + gi * H
	fig := a.suite.Point().Base().Mul(nil, fi.V)
	H := deriveH(a.suite, a.verifiers)
	gih := a.suite.Point().Mul(H, gi.V)
	ci := a.suite.Point().Add(fig, gih)

	commitPoly := NewPubPoly(a.suite, nil, d.Commitments)

	pubShare := commitPoly.Eval(fi.I)
	if !ci.Equal(pubShare.V) {
		return errors.New("deal: share do not verify against commitments")
	}
	return nil
}

func (a *aggregator) verifyComplaint(c *Complaint, incComplaint bool) error {
	if err := a.verifyDeal(c.Deal, false); err == nil {
		return errors.New("complaint: invalid because contains a valid deal")
	}
	if _, ok := a.complaints[c.Public.String()]; incComplaint && ok {
		return errors.New("complaint: already stored one from same origin")
	}

	idx, ok := findIndex(a.verifiers, c.Public)
	if !ok {
		return errors.New("complaint: from unknown participant")
	}

	if err := sign.VerifySchnorr(a.suite, c.Public, a.sid, c.Signature); err != nil {
		return err
	}

	if idx >= len(a.verifiers) {
		return errors.New("complaint: out-of-bound index")
	}
	a.complaints[c.Public.String()] = c
	return nil
}

func (a *aggregator) verifyApproval(ap *Approval) error {
	if _, ok := a.approvals[ap.Public.String()]; ok {
		return errors.New("approval: already stored one from same origin")
	}

	if err := sign.VerifySchnorr(a.suite, ap.Public, a.sid, ap.Signature); err != nil {
		return err
	}

	a.approvals[ap.Public.String()] = ap
	return nil
}

func (a *aggregator) EnoughApprovals() bool {
	if a.deal == nil {
		return false
	}
	return len(a.approvals) >= a.t
}

func (a *aggregator) DealCertified() bool {
	if len(a.complaints) >= a.t-1 {
		return false
	}
	return true
}

func minimumT(verifiers []abstract.Point) int {
	return (len(verifiers) + 1) / 2
}

func validT(t int, verifiers []abstract.Point) bool {
	return t >= minimumT(verifiers) && t <= len(verifiers) && int(uint32(t)) == t
}

// HashFunc is used to compute
//  - the second base H out of a list of public keys
//  - the hash of the message to sign in a Complaint
var HashFunc = sha256.New

func deriveH(suite abstract.Suite, verifiers []abstract.Point) abstract.Point {
	var b bytes.Buffer
	for i := range verifiers {
		verifiers[i].MarshalTo(&b)
	}
	h := HashFunc()
	h.Write(b.Bytes())
	digest := h.Sum(nil)
	base, _ := suite.Point().Pick(nil, suite.Cipher(digest))
	return base
}

func findIndex(verifiers []abstract.Point, public abstract.Point) (int, bool) {
	for i := range verifiers {
		if verifiers[i].Equal(public) {
			return i, true
		}
	}
	return 0, false
}

func sessionID(dealer abstract.Point, verifiers, commitments []abstract.Point, t int) ([]byte, error) {
	h := HashFunc()
	if _, err := dealer.MarshalTo(h); err != nil {
		return nil, err
	}

	for i := range verifiers {
		if _, err := verifiers[i].MarshalTo(h); err != nil {
			return nil, err
		}
	}

	for i := range commitments {
		if _, err := commitments[i].MarshalTo(h); err != nil {
			return nil, err
		}
	}
	if err := binary.Write(h, binary.LittleEndian, uint32(t)); err != nil {
		return nil, err
	}
	return h.Sum(nil), nil
}
