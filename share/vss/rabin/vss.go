// Package vss implements the verifiable secret sharing scheme from the
// paper "Provably Secure Distributed Schnorr Signatures and a (t, n) Threshold
// Scheme for Implicit Certificates".
// VSS enables a dealer to share a secret securely and verifiably among n
// participants out of which at least t are required for its reconstruction.
// The verifiability of the process prevents a
// malicious dealer from influencing the outcome to his advantage as each
// verifier can check the validity of the received share. The protocol has the
// following steps:
//
//  1. The dealer send a Deal to every verifiers using `Deals()`. Each deal must
//     be sent securely to one verifier whose public key is at the same index than
//     the index of the Deal.
//
//  2. Each verifier processes the Deal with `ProcessDeal`.
//     This function returns a Response which can be twofold:
//     - an approval, to confirm a correct deal
//     - a complaint to announce an incorrect deal notifying others that the
//     dealer might be malicious.
//     All Responses must be broadcasted to every verifiers and the dealer.
//
//  3. The dealer can respond to each complaint by a justification revealing the
//     share he originally sent out to the accusing verifier. This is done by
//     calling `ProcessResponse` on the `Dealer`.
//
//  4. The verifiers refuse the shared secret and abort the protocol if there
//     are at least t complaints OR if a Justification is wrong. The verifiers
//     accept the shared secret if there are at least t approvals at which point
//     any t out of n verifiers can reveal their shares to reconstruct the shared
//     secret.
package vss

import (
	"bytes"
	"errors"
	"fmt"

	"go.dedis.ch/kyber/v4"
	"go.dedis.ch/kyber/v4/share"
	"go.dedis.ch/kyber/v4/share/vss"
	"go.dedis.ch/kyber/v4/sign/schnorr"
)

// NewDealer returns a Dealer capable of leading the secret sharing scheme. It
// does not have to be trusted by other Verifiers. The security parameter t is
// the number of shares required to reconstruct the secret. MinimumT() provides
// a middle ground between robustness and secrecy. Increasing t will increase
// the secrecy at the cost of the decreased robustness and vice versa. It
// returns an error if the t is inferior or equal to 2.
func NewDealer(suite vss.Suite, longterm, secret kyber.Scalar, verifiers []kyber.Point, t int) (*vss.Dealer, error) {
	if !vss.ValidT(t, verifiers) {
		return nil, fmt.Errorf("dealer: t %d invalid", t)
	}

	H := deriveH(suite, verifiers)
	f := share.NewPriPoly(suite, t, secret, suite.RandomStream())
	g := share.NewPriPoly(suite, t, nil, suite.RandomStream())
	pub := suite.Point().Mul(longterm, nil)

	// Compute public polynomial coefficients
	F := f.Commit(suite.Point().Base())
	_, secretCommits := F.Info()
	G := g.Commit(H)

	C, err := F.Add(G)
	if err != nil {
		return nil, err
	}
	_, commitments := C.Info()

	sessionID, err := vss.SessionID(suite, pub, verifiers, commitments, t)
	if err != nil {
		return nil, err
	}

	aggregator := NewAggregator(suite, pub, verifiers, commitments, t, sessionID)
	// C = F + G
	deals := make([]*vss.Deal, len(verifiers))
	for i := range verifiers {
		idx := uint32(i)
		fi := f.Eval(idx)
		gi := g.Eval(idx)
		deals[i] = &vss.Deal{
			SessionID:   sessionID,
			SecShare:    fi,
			RndShare:    gi,
			Commitments: commitments,
			T:           uint32(t),
		}
	}

	hkdfContext, err := vss.Context(suite, pub, verifiers)
	if err != nil {
		return nil, err
	}

	d := vss.NewDealer(suite, longterm, secret, pub, secretCommits,
		verifiers, hkdfContext, t, sessionID, deals, aggregator)

	return d, nil
}

// Aggregator implements vss.Aggregator
type Aggregator struct {
	suite     vss.Suite
	dealer    kyber.Point
	verifiers []kyber.Point
	commits   []kyber.Point

	responses map[uint32]*vss.Response
	sid       []byte
	deal      *vss.Deal
	t         int
	badDealer bool
}

func NewAggregator(
	suite vss.Suite,
	dealer kyber.Point,
	verifiers,
	commitments []kyber.Point,
	t int,
	sid []byte,
) *Aggregator {
	agg := &Aggregator{
		suite:     suite,
		dealer:    dealer,
		verifiers: verifiers,
		commits:   commitments,
		t:         t,
		sid:       sid,
		responses: make(map[uint32]*vss.Response),
	}
	return agg
}

func NewEmptyAggregator(suite vss.Suite, verifiers []kyber.Point) *Aggregator {
	return &Aggregator{
		suite:     suite,
		verifiers: verifiers,
		responses: make(map[uint32]*vss.Response),
	}
}

func (a *Aggregator) Deal() *vss.Deal {
	return a.deal
}

func (a *Aggregator) HasDeal() bool {
	return a.deal != nil
}

func (a *Aggregator) Sid() []byte {
	return a.sid
}

func (a *Aggregator) SetTimeout() {
	a.cleanVerifiers()
}

func (a *Aggregator) VerifyDeal(d *vss.Deal, inclusion bool) error {
	if a.deal != nil && inclusion {
		return vss.ErrDealAlreadyProcessed

	}
	if a.deal == nil {
		a.commits = d.Commitments
		a.sid = d.SessionID
		a.deal = d
	}

	if !vss.ValidT(int(d.T), a.verifiers) {
		return errors.New("vss: invalid t received in Deal")
	}

	if !bytes.Equal(a.sid, d.SessionID) {
		return errors.New("vss: find different sessionIDs from Deal")
	}

	fi := d.SecShare
	gi := d.RndShare
	if fi.I != gi.I {
		return errors.New("vss: not the same index for f and g share in Deal")
	}
	if fi.I >= uint32(len(a.verifiers)) {
		return errors.New("vss: index out of bounds in Deal")
	}
	// compute fi * G + gi * H
	fig := a.suite.Point().Base().Mul(fi.V, nil)
	H := deriveH(a.suite, a.verifiers)
	gih := a.suite.Point().Mul(gi.V, H)
	ci := a.suite.Point().Add(fig, gih)

	commitPoly := share.NewPubPoly(a.suite, nil, d.Commitments)

	pubShare := commitPoly.Eval(fi.I)
	if !ci.Equal(pubShare.V) {
		return errors.New("vss: share does not verify against commitments in Deal")
	}
	return nil
}

// cleanVerifiers checks the Aggregator's response array and creates a StatusComplaint
// response for all verifiers who have no response in the array.
func (a *Aggregator) cleanVerifiers() {
	for i := range a.verifiers {
		if _, ok := a.responses[uint32(i)]; !ok {
			a.responses[uint32(i)] = &vss.Response{
				SessionID:      a.sid,
				Index:          uint32(i),
				StatusApproved: vss.StatusComplaint,
			}
		}
	}
}

func (a *Aggregator) VerifyResponse(r *vss.Response) error {
	if !bytes.Equal(r.SessionID, a.sid) {
		return errors.New("vss: receiving inconsistent sessionID in response")
	}

	pub, ok := vss.FindPub(a.verifiers, r.Index)
	if !ok {
		return errors.New("vss: index out of bounds in response")
	}

	msg, err := r.Hash(a.suite)
	if err != nil {
		return err
	}

	if err := schnorr.Verify(a.suite, pub, msg, r.Signature); err != nil {
		return err
	}

	return a.AddResponse(r)
}

func (a *Aggregator) VerifyJustification(j *vss.Justification) error {
	if _, ok := vss.FindPub(a.verifiers, j.Index); !ok {
		return errors.New("vss: index out of bounds in justification")
	}
	r, ok := a.responses[j.Index]
	if !ok {
		return errors.New("vss: no complaints received for this justification")
	}
	if r.StatusApproved {
		return errors.New("vss: justification received for an approval")
	}

	if err := a.VerifyDeal(j.Deal, false); err != nil {
		// if one response is bad, flag the dealer as malicious
		a.badDealer = true
		return err
	}
	r.StatusApproved = vss.StatusApproval
	return nil
}

func (a *Aggregator) AddResponse(r *vss.Response) error {
	if _, ok := vss.FindPub(a.verifiers, r.Index); !ok {
		return errors.New("vss: index out of bounds in Complaint")
	}
	if _, ok := a.responses[r.Index]; ok {
		return errors.New("vss: already existing response from same origin")
	}
	a.responses[r.Index] = r
	return nil
}

func (a *Aggregator) EnoughApprovals() bool {
	var app int
	for _, r := range a.responses {
		if r.StatusApproved {
			app++
		}
	}
	return app >= a.t
}

// DealCertified returns true if there has been less than t complaints, all
// Justifications were correct and if EnoughApprovals() returns true.
func (a *Aggregator) DealCertified() bool {
	// a can be nil if we're calling it before receiving a deal
	if a == nil {
		return false
	}

	var verifiersUnstable int
	// Check either a StatusApproval or StatusComplaint for all known verifiers
	// i.e. make sure all verifiers are either timed-out or OK.
	for i := range a.verifiers {
		if _, ok := a.responses[uint32(i)]; !ok {
			verifiersUnstable++
		}
	}

	tooMuchComplaints := verifiersUnstable > 0 || a.badDealer
	return a.EnoughApprovals() && !tooMuchComplaints
}

// UnsafeSetResponseDKG is an UNSAFE bypass method to allow DKG to use VSS
// that works on basis of approval only.
func (a *Aggregator) UnsafeSetResponseDKG(idx uint32, approval bool) {
	r := &vss.Response{
		SessionID:      a.sid,
		Index:          idx,
		StatusApproved: approval,
	}

	//nolint:errcheck // Unsafe function
	a.AddResponse(r)
}

func deriveH(suite vss.Suite, verifiers []kyber.Point) kyber.Point {
	var b bytes.Buffer
	for _, v := range verifiers {
		_, _ = v.MarshalTo(&b)
	}
	base := suite.Point().Pick(suite.XOF(b.Bytes()))
	return base
}
