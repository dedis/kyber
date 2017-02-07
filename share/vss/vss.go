// vss.go implements the verifiable secret sharing scheme by Pedersen recalled
// in "Provably Secure Distributed Schnorr Signatures and a (t, n) Threshold
// Scheme for Implicit Certificates"  by Stinson and Strobl.
// The basic scheme is taken from Pedersen's paper: "Non-interactive and
// information-theoretic secure verifiable secret sharing", in Crypto ’91, pages
// 129–140, 1991.
// At a higher level, you have one party called the Dealer who wishes to share a
// secret securly between other parties, called the Verifiers. In this scheme,
// neither the verifiers or the dealer is deemed trustworthy, but rather, the
// assumptions is that the adversary has at most t verifiers amongst n, or the
// dealer is malicious. In that case, there needs to be some way for Verifiers to
// check the correctness of the shares they receive. This is the scheme goal.
// 1) The dealer send a Deal to every verifiers using `Deals()`
// 2) Each verifier process the Deal with `ProcessDeal`. They can either return:
//    - an Approval, which means the deal seems correct
//    - an Complaint, which means the deal is not correct and the dealer might
//    be malicious.
// 3) The dealer can respond to each Complaint by a Justification, basically
// revealing the share he sent out to the original "complainer"
// 4) All verifiers accept the deal iif there has been at least t Approval. They
// refuse the deal if there has been more than t-1 complaints OR if a
// Justification is wrong.
// At the end of the scheme, all verifiers can re-unite their Share to
// reconstruct the original secret. Only t out of n verifiers are needed.
package vss

import (
	"bytes"
	"crypto/cipher"
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/dedis/crypto/abstract"
	"github.com/dedis/crypto/share"
	"github.com/dedis/crypto/sign"
)

// Dealer is responsible for creating the shares, distribute them and reply to
// any Complaints.
type Dealer struct {
	suite abstract.Suite

	reader cipher.Stream
	long   abstract.Scalar
	pub    abstract.Point

	secret        abstract.Scalar
	secretCommits []abstract.Point

	verifiers []abstract.Point
	// threshold of shares that is needed to reconstruct the secret
	t int
	// sessionID is a unique identifier for the whole session of the scheme
	sessionID []byte

	// list of deals this Dealer has generated
	deals []*Deal
	*aggregator
}

// Deal is sent by the Dealer to each participants.
type Deal struct {
	SessionID   []byte
	SecShare    *share.PriShare
	RndShare    *share.PriShare
	T           uint32
	Commitments []abstract.Point
	Signature   []byte
}

type Response struct {
	SessionID []byte
	Index     uint32
	// 0 = NO APPROVAL == Complaint , 1 = APPROVAL
	Status    byte
	Signature []byte
}

const (
	StatusComplaint byte = iota
	StatusApproval
)

// Justification is a message that is broadcasted by the Dealer in response to
// a Complaint. It contains the original Complaint as well as the shares
// distributed to the complainer.
type Justification struct {
	SessionID []byte
	// Index of the verifier who issued the Complaint,i.e. index of this Deal
	Index     uint32
	Deal      *Deal
	Signature []byte
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
	}
	if !validT(t, verifiers) {
		return nil, fmt.Errorf("dealer: t %d invalid.", t)
	}

	d.t = t

	H := deriveH(d.suite, d.verifiers)
	f := share.NewPriPoly(d.suite, d.t, d.secret, r)
	g := share.NewPriPoly(d.suite, d.t, nil, r)
	d.pub = d.suite.Point().Mul(nil, d.long)

	// F = coeff * B
	F := f.Commit(d.suite.Point().Base())
	_, d.secretCommits = F.Info()
	// G = coeff * H
	G := g.Commit(H)

	C, err := F.Add(G)
	if err != nil {
		return nil, err
	}
	_, commitments := C.Info()

	d.sessionID, err = sessionID(d.suite, d.pub, d.verifiers, commitments, d.t)
	if err != nil {
		return nil, err
	}

	d.aggregator = newAggregator(d.suite, d.pub, d.verifiers, commitments, d.t, d.sessionID)
	// C = F + G
	d.deals = make([]*Deal, len(d.verifiers))
	for i := range d.verifiers {
		fi := f.Eval(i)
		gi := g.Eval(i)
		d.deals[i] = &Deal{
			SessionID:   d.sessionID,
			SecShare:    fi,
			RndShare:    gi,
			Commitments: commitments,
			T:           uint32(d.t),
		}
		if d.deals[i].Signature, err = sign.Schnorr(d.suite, d.long, msgDeal(d.deals[i])); err != nil {
			return nil, err
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

// ProcessComplaint analyzes the given complaint. If it's a valid complaint,
// then it returns a Justification. This response must be broadcasted to every
// participants. If it's an invalid complaint, it returns an error about the
// complaints. The verifiers will also ignore an invalid Complaint.
func (d *Dealer) ProcessResponse(r *Response) (*Justification, error) {
	if err := d.verifyResponse(r); err != nil {
		return nil, err
	}
	if r.Status == StatusApproval {
		return nil, nil
	}

	j := &Justification{
		SessionID: d.sessionID,
		// index is guaranteed to be good because of d.verifyComplaint before
		Index: r.Index,
		Deal:  d.deals[int(r.Index)],
	}
	sig, err := sign.Schnorr(d.suite, d.long, msgJustification(j))
	if err != nil {
		return nil, err
	}
	j.Signature = sig
	return j, nil
}

// SecretCommit returns the commitment of the secret being shared by this
// dealer. This function is only to be called once the deal has enough approvals
// and is verified otherwise it returns nil.
func (d *Dealer) SecretCommit() abstract.Point {
	if !d.EnoughApprovals() || !d.DealCertified() {
		return nil
	}
	return d.suite.Point().Mul(nil, d.secret)
}

func (d *Dealer) Commits() []abstract.Point {
	if !d.EnoughApprovals() || !d.DealCertified() {
		return nil
	}
	return d.secretCommits
}

func (d *Dealer) Key() (abstract.Scalar, abstract.Point) {
	return d.long, d.pub
}

func (d *Dealer) SessionID() []byte {
	return d.sessionID
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

	*aggregator
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
	for i := range verifiers {
		if verifiers[i].Equal(v.pub) {
			ok = true
			v.index = i
			break
		}
	}
	if !ok {
		return nil, errors.New("vss: public key not found in the list of verifiers")
	}

	v.h = deriveH(suite, verifiers)
	return v, nil
}

// ProcessDeal takes a Deal, tries to decrypt it and see if it is correct or
// not. In case the Deal is correct,ie. the verifier can verify the shares
// against the public coefficients, an Approval is returned and must be
// broadcasted to every participants including the Dealer. In case the Deal
// is not correct because of the public polynomial checking, or the indexes are
// not the same, or the session identifier is wrong, it returns a Complaint
// which must be broadcasted to every participants including the Dealer.
// If the complaint is deemed invalid because of a wrong index (not the same as
// the verifier) or because the verifier already received a Deal, it does not
// return a complaint.
// ProcessDeal returns an error in any case to let the user know what was the
// error.
// XXX API question: return value.For the moment, the default is to let the user
// know everything that is wrong through the error.
func (v *Verifier) ProcessDeal(d *Deal) (*Response, error) {
	if d.SecShare.I != v.index {
		return nil, errors.New("vss: verifier got wrong index from deal")
	}

	t := int(d.T)

	sid, err := sessionID(v.suite, v.dealer, v.verifiers, d.Commitments, t)
	if err != nil {
		return nil, err
	}

	if v.aggregator == nil {
		v.aggregator = newAggregator(v.suite, v.dealer, v.verifiers, d.Commitments, t, d.SessionID)
	}

	r := &Response{
		SessionID: sid,
		Index:     uint32(v.index),
		Status:    StatusApproval,
	}
	if err = v.verifyDeal(d, true); err != nil {
		r.Status = StatusComplaint
	}

	if err == errDealAlreadyProcessed {
		return nil, err
	}

	if r.Signature, err = sign.Schnorr(v.suite, v.long, msgResponse(r)); err != nil {
		return nil, err
	}

	if err = v.aggregator.addResponse(r); err != nil {
		return nil, err
	}

	return r, nil
}

func (v *Verifier) ProcessResponse(resp *Response) error {
	return v.aggregator.verifyResponse(resp)
}

// Share returns the Deal that this verifier has received. It returns
// nil if the deal is not certified or there is not enough approvals.
func (v *Verifier) Deal() *Deal {
	if !v.EnoughApprovals() || !v.DealCertified() {
		return nil
	}
	return v.deal
}

// ProcessJustification takes a DealerResponse and returns an error if
// something went wrong during the verification. If it is the case, that
// probably means the Dealer is acting maliciously. In order to be sure, call
// v.EnoughApprovals() and if true, v.IsDealGood().
// NOTE: it does *not* verify the complaint associated with since it is supposed
// to already have received it.
func (v *Verifier) ProcessJustification(dr *Justification) error {
	return v.aggregator.verifyJustification(dr)
}

func (v *Verifier) Key() (abstract.Scalar, abstract.Point) {
	return v.long, v.pub
}

func (v *Verifier) Index() int {
	return v.index
}

// SessionID returns the session id generated by the Dealer. WARNING: it returns
// an nil slice if the verifier has not received the Deal yet !
func (v *Verifier) SessionID() []byte {
	return v.sid
}

type aggregator struct {
	suite     abstract.Suite
	dealer    abstract.Point
	verifiers []abstract.Point
	commits   []abstract.Point

	responses map[uint32]*Response
	sid       []byte
	deal      *Deal
	t         int
	badDealer bool
}

func newAggregator(suite abstract.Suite, dealer abstract.Point, verifiers, commitments []abstract.Point, t int, sid []byte) *aggregator {
	agg := &aggregator{
		suite:     suite,
		dealer:    dealer,
		verifiers: verifiers,
		commits:   commitments,
		t:         t,
		sid:       sid,
		responses: make(map[uint32]*Response),
	}
	return agg
}

// used only by the Dealer
func (a *aggregator) setDeal(d *Deal) {
	a.deal = d
}

var errDealAlreadyProcessed = errors.New("vss: verifier already received a deal")

func (a *aggregator) verifyDeal(d *Deal, inclusion bool) error {
	if a.deal != nil && inclusion {
		return errDealAlreadyProcessed

	}
	if a.deal == nil {
		a.commits = d.Commitments
		a.sid = d.SessionID
		a.deal = d
	}

	if !validT(int(d.T), a.verifiers) {
		return errors.New("vss: invalid t received in Deal")
	}

	if !bytes.Equal(a.sid, d.SessionID) {
		return errors.New("vss: find different sessionIDs from Deal")
	}

	if err := sign.VerifySchnorr(a.suite, a.dealer, msgDeal(d), d.Signature); err != nil {
		return err
	}

	fi := d.SecShare
	gi := d.RndShare
	if fi.I != gi.I {
		return errors.New("vss: not the same index for f and g share in Deal")
	} else if fi.I < 0 || fi.I >= len(a.verifiers) {
		return errors.New("vss: index out of bounds in Deal")
	}
	// compute fi * G + gi * H
	fig := a.suite.Point().Base().Mul(nil, fi.V)
	H := deriveH(a.suite, a.verifiers)
	gih := a.suite.Point().Mul(H, gi.V)
	ci := a.suite.Point().Add(fig, gih)

	commitPoly := share.NewPubPoly(a.suite, nil, d.Commitments)

	pubShare := commitPoly.Eval(fi.I)
	if !ci.Equal(pubShare.V) {
		return errors.New("vss: share do not verify against commitments in Deal")
	}
	return nil
}

func (a *aggregator) verifyResponse(r *Response) error {
	if !bytes.Equal(r.SessionID, a.sid) {
		return errors.New("vss: receiving inconsistent sessionID in response")
	}

	pub, ok := findPub(a.verifiers, r.Index)
	if !ok {
		return errors.New("vss: index out of bounds in response")
	}

	if err := sign.VerifySchnorr(a.suite, pub, msgResponse(r), r.Signature); err != nil {
		return err
	}

	return a.addResponse(r)
}

func (a *aggregator) verifyJustification(j *Justification) error {
	if _, ok := findPub(a.verifiers, j.Index); !ok {
		return errors.New("vss: index out of bounds in justification")
	}
	r, ok := a.responses[j.Index]
	if !ok {
		return errors.New("vss: no complaints received for this justification")
	} else if r.Status != StatusComplaint {
		return errors.New("vss: justification received for an approval")
	}

	if err := a.verifyDeal(j.Deal, false); err != nil {
		// if one response is bad, flag the dealer as malicious
		a.badDealer = true
		return err
	}
	// "deletes" the complaint since the dealer is honest
	r.Status = StatusApproval
	return nil
}

func (a *aggregator) addResponse(r *Response) error {
	if _, ok := findPub(a.verifiers, r.Index); !ok {
		return errors.New("vss: index out of bounds in Complaint")
	}
	if _, ok := a.responses[r.Index]; ok {
		return errors.New("vss: already existing response from same origin")
	}
	a.responses[r.Index] = r
	return nil
}

func (a *aggregator) EnoughApprovals() bool {
	var app int
	for _, r := range a.responses {
		if r.Status == StatusApproval {
			app++
		}
	}
	return app >= a.t
}

func (a *aggregator) DealCertified() bool {
	var comps int
	for _, r := range a.responses {
		if r.Status == StatusComplaint {
			comps++
		}
	}
	return a.EnoughApprovals() && !(comps >= a.t || a.badDealer)
}

func MinimumT(n int) int {
	return (n + 1) / 2
}

func validT(t int, verifiers []abstract.Point) bool {
	return t >= 2 && t <= len(verifiers) && int(uint32(t)) == t
}

func deriveH(suite abstract.Suite, verifiers []abstract.Point) abstract.Point {
	var b bytes.Buffer
	for i := range verifiers {
		verifiers[i].MarshalTo(&b)
	}
	h := suite.Hash()
	h.Write(b.Bytes())
	digest := h.Sum(nil)
	base, _ := suite.Point().Pick(nil, suite.Cipher(digest))
	return base
}

func findPub(verifiers []abstract.Point, idx uint32) (abstract.Point, bool) {
	iidx := int(idx)
	if iidx >= len(verifiers) {
		return nil, false
	}
	return verifiers[iidx], true
}

func sessionID(suite abstract.Suite, dealer abstract.Point, verifiers, commitments []abstract.Point, t int) ([]byte, error) {
	h := suite.Hash()
	dealer.MarshalTo(h)

	for i := range verifiers {
		verifiers[i].MarshalTo(h)
	}

	for i := range commitments {
		commitments[i].MarshalTo(h)
	}
	binary.Write(h, binary.LittleEndian, uint32(t))

	return h.Sum(nil), nil
}

func msgResponse(r *Response) []byte {
	var buf bytes.Buffer
	buf.WriteString("response")
	buf.Write(r.SessionID)
	binary.Write(&buf, binary.LittleEndian, r.Index)
	binary.Write(&buf, binary.LittleEndian, r.Status)
	return buf.Bytes()
}

func msgDeal(d *Deal) []byte {
	var buf bytes.Buffer
	buf.WriteString("deal")
	buf.Write(d.SessionID) // sid already includes all other info
	binary.Write(&buf, binary.LittleEndian, d.SecShare.I)
	d.SecShare.V.MarshalTo(&buf)
	binary.Write(&buf, binary.LittleEndian, d.RndShare.I)
	d.RndShare.V.MarshalTo(&buf)
	return buf.Bytes()
}

func msgJustification(j *Justification) []byte {
	var buf bytes.Buffer
	buf.Write(j.SessionID)
	binary.Write(&buf, binary.LittleEndian, j.Index)
	buf.Write(msgDeal(j.Deal))
	return buf.Bytes()
}
