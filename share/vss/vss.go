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

	secret abstract.Scalar

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

// Complaint is a message that must be broadcasted to every verifiers when
// a verifier receives an invalid Deal.
type Complaint struct {
	SessionID []byte
	Index     uint32
	Deal      *Deal
	Signature []byte
}

// Justification is a message that is broadcasted by the Dealer in response to
// a Complaint. It contains the original Complaint as well as the shares
// distributed to the complainer.
type Justification struct {
	Complaint *Complaint
	Deal      *Deal
}

// Approval is a message that is sent if a verifier approves the Deal he
// received from the Dealer.
type Approval struct {
	SessionID []byte
	Index     uint32
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
	pub := d.suite.Point().Mul(nil, d.long)

	// F = coeff * B
	F := f.Commit(d.suite.Point().Base())
	// G = coeff * H
	G := g.Commit(H)

	C, err := F.Add(G)
	if err != nil {
		return nil, err
	}
	_, commitments := C.Info()

	d.sessionID, err = sessionID(d.suite, pub, d.verifiers, commitments, d.t)
	if err != nil {
		return nil, err
	}

	d.aggregator = newAggregator(d.suite, pub, d.verifiers, commitments, d.t, d.sessionID)
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
func (d *Dealer) ProcessComplaint(c *Complaint) (*Justification, error) {
	if err := d.verifyComplaint(c); err != nil {
		return nil, err
	}
	return &Justification{
		// index is guaranteed to be good because of d.verifyComplaint before
		Deal:      d.deals[int(c.Index)],
		Complaint: c,
	}, nil
}

// ProcessApprovals looks if the approval is legitimate and stores it. If the
// approval is not legitimate or has already been received, it returns an error.
// To knoew whether participants approved the sharing, call `d.EnoughApproval`
// and if true, `d.DealCertified`.
func (d *Dealer) ProcessApprovals(a *Approval) error {
	return d.verifyApproval(a)
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
			break
		}
	}
	if !ok {
		return nil, errors.New("verifier: public key not found in the list of verifiers")
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
func (v *Verifier) ProcessDeal(d *Deal) (*Approval, *Complaint, error) {
	if d.SecShare.I != v.index {
		return nil, nil, errors.New("verifier: wrong index from deal")
	}

	t := int(d.T)

	sid, err := sessionID(v.suite, v.dealer, v.verifiers, d.Commitments, t)
	if err != nil {
		return nil, nil, err
	}

	if v.aggregator == nil {
		v.aggregator = newAggregator(v.suite, v.dealer, v.verifiers, d.Commitments, t, d.SessionID)
	}

	if err := v.verifyDeal(d, true); err != nil {
		if err == errDealAlreadyProcessed {
			return nil, nil, err
		}
		c := &Complaint{
			SessionID: sid,
			Index:     uint32(v.index),
			Deal:      d,
		}
		var err2 error
		if c.Signature, err2 = sign.Schnorr(v.suite, v.long, msgComplaint(c)); err2 != nil {
			return nil, nil, err2
		}

		if err2 = v.aggregator.addComplaint(c); err2 != nil {
			return nil, nil, err2
		}
		return nil, c, err
	}
	ap := &Approval{
		Index:     uint32(v.index),
		SessionID: v.sid,
	}
	if ap.Signature, err = sign.Schnorr(v.suite, v.long, msgApproval(ap)); err != nil {
		return nil, nil, err
	}
	return ap, nil, v.aggregator.addApproval(ap)
}

// Share returns the private share that this verifier has received. It returns
// nil if the deal is not certified or there is not enough approvals.
func (v *Verifier) Share() *share.PriShare {
	if !v.EnoughApprovals() || !v.DealCertified() {
		return nil
	}
	return v.deal.SecShare
}

// ProcessComplaint takes a Complaint and stores it if the Complaint is valid.
// If the verifier already saw a Complaint from the same origin, it returns an error.
// If the Complaint is not valid, it returns an error. That does NOT mean the
// Deal is not good, but rather only this Complaint is not valid and should not
// be treated.  To know whether the deal is good, call first v.EnoughApproval(),
// and if true, call v.IsDealGood().
func (v *Verifier) ProcessComplaint(c *Complaint) error {
	return v.verifyComplaint(c)
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

func (v *Verifier) ProcessApproval(ap *Approval) error {
	return v.verifyApproval(ap)
}

type aggregator struct {
	suite     abstract.Suite
	dealer    abstract.Point
	verifiers []abstract.Point
	commits   []abstract.Point

	complaints map[uint32]*Complaint
	approvals  map[uint32]*Approval
	sid        []byte
	deal       *Deal
	t          int
	badDealer  bool
}

func newAggregator(suite abstract.Suite, dealer abstract.Point, verifiers, commitments []abstract.Point, t int, sid []byte) *aggregator {
	agg := &aggregator{
		suite:      suite,
		dealer:     dealer,
		verifiers:  verifiers,
		commits:    commitments,
		t:          t,
		sid:        sid,
		complaints: make(map[uint32]*Complaint),
		approvals:  make(map[uint32]*Approval),
	}
	return agg
}

// used only by the Dealer
func (a *aggregator) setDeal(d *Deal) {
	a.deal = d
}

var errDealAlreadyProcessed = errors.New("deal: already received a deal")

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
		return errors.New("verifier: invalid t received in Deal")
	}

	if !bytes.Equal(a.sid, d.SessionID) {
		return errors.New("deal: sessionID is different from locally computed")
	}

	if err := sign.VerifySchnorr(a.suite, a.dealer, msgDeal(d), d.Signature); err != nil {
		return err
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

	commitPoly := share.NewPubPoly(a.suite, nil, d.Commitments)

	pubShare := commitPoly.Eval(fi.I)
	if !ci.Equal(pubShare.V) {
		return errors.New("deal: share do not verify against commitments")
	}
	return nil
}

func (a *aggregator) verifyComplaint(c *Complaint) error {
	if err := a.verifyDeal(c.Deal, false); err == nil {
		return errors.New("complaint: invalid because contains a valid deal")
	}
	if !bytes.Equal(c.SessionID, a.sid) {
		return errors.New("complaint: receiving inconsistent sessionID")
	}

	pub, ok := findPub(a.verifiers, c.Index)
	if !ok {
		return errors.New("complaint: index out of bounds")
	}

	if err := sign.VerifySchnorr(a.suite, pub, msgComplaint(c), c.Signature); err != nil {
		return err
	}

	return a.addComplaint(c)
}

func (a *aggregator) verifyApproval(ap *Approval) error {
	if a.deal == nil {
		return errors.New("approval: deal has not been received")
	}
	if !bytes.Equal(ap.SessionID, a.sid) {
		return errors.New("approval: does not match session id recorded")
	}

	pub, ok := findPub(a.verifiers, ap.Index)
	if !ok {
		return errors.New("approval: index out of bounds")
	}

	if err := sign.VerifySchnorr(a.suite, pub, msgApproval(ap), ap.Signature); err != nil {
		return err
	}

	return a.addApproval(ap)
}

func (a *aggregator) verifyJustification(dr *Justification) error {
	if _, ok := findPub(a.verifiers, dr.Complaint.Index); !ok {
		return errors.New("verifier: complaint's index out of bounds.")
	}
	if _, ok := a.complaints[dr.Complaint.Index]; !ok {
		return errors.New("verifier: no complaints received for this justification")
	}
	// XXX should we verify the correctness of the complaint

	if err := a.verifyDeal(dr.Deal, false); err != nil {
		// if one response is bad, flag the dealer as malicious
		a.badDealer = true
		return err
	}
	// "deletes" the complaint since the dealer is honest
	delete(a.complaints, dr.Complaint.Index)
	return nil
}

func (a *aggregator) addComplaint(c *Complaint) error {
	if _, ok := findPub(a.verifiers, c.Index); !ok {
		return errors.New("complaint: index out of bounds")
	}
	if _, ok := a.complaints[c.Index]; ok {
		return errors.New("complaint: already existing complaint from same origin")
	} else if _, ok := a.approvals[c.Index]; ok {
		return errors.New("complaint: approval existing from same origin")

	}
	a.complaints[c.Index] = c
	return nil
}

func (a *aggregator) addApproval(ap *Approval) error {
	if _, ok := findPub(a.verifiers, ap.Index); !ok {
		return errors.New("approval: index out of bounds")
	}
	if _, ok := a.complaints[ap.Index]; ok {
		return errors.New("approval: complaint existing from same origin")
	} else if _, ok := a.approvals[ap.Index]; ok {
		return errors.New("approval: approval already existing from same origin")
	}
	a.approvals[ap.Index] = ap
	return nil
}

func (a *aggregator) EnoughApprovals() bool {
	return len(a.approvals) >= a.t
}

func (a *aggregator) DealCertified() bool {
	return a.EnoughApprovals() && !(len(a.complaints) >= a.t || a.badDealer)
}

func minimumT(verifiers []abstract.Point) int {
	return (len(verifiers) + 1) / 2
}

func validT(t int, verifiers []abstract.Point) bool {
	return t >= minimumT(verifiers) && t <= len(verifiers) && int(uint32(t)) == t
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

func msgApproval(a *Approval) []byte {
	var buf bytes.Buffer
	buf.WriteString("approval")
	buf.Write(a.SessionID)
	binary.Write(&buf, binary.LittleEndian, a.Index)
	return buf.Bytes()
}

func msgComplaint(c *Complaint) []byte {
	var buf bytes.Buffer
	buf.WriteString("complaint")
	buf.Write(c.SessionID)
	binary.Write(&buf, binary.LittleEndian, c.Index)
	buf.Write(msgDeal(c.Deal))
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
