// Package vss implements the verifiable secret sharing scheme from
// "Non-Interactive and Information-Theoretic Secure Verifiable Secret Sharing"
// by Torben Pryds Pedersen.
// https://link.springer.com/content/pdf/10.1007/3-540-46766-1_9.pdf
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

	f := share.NewPriPoly(suite, t, secret, suite.RandomStream())
	pub := suite.Point().Mul(longterm, nil)

	// Compute public polynomial coefficients
	F := f.Commit(suite.Point().Base())
	_, secretCommits := F.Info()

	var err error
	sessionID, err := vss.SessionID(suite, pub, verifiers, secretCommits, t)
	if err != nil {
		return nil, err
	}

	aggregator := newAggregator(suite, pub, verifiers, secretCommits, t, sessionID)
	// C = F + G
	deals := make([]*vss.Deal, len(verifiers))
	for i := range verifiers {
		fi := f.Eval(uint32(i))
		deals[i] = &vss.Deal{
			SessionID:   sessionID,
			SecShare:    fi,
			Commitments: secretCommits,
			T:           uint32(t),
		}
	}

	hkdfContext, err := vss.Context(suite, pub, verifiers)
	if err != nil {
		return nil, err
	}

	d := vss.NewDealer(suite, longterm, secret, pub,
		secretCommits, verifiers, hkdfContext, t, sessionID,
		deals, aggregator)

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
	timeout   bool
}

func newAggregator(
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

// NewEmptyAggregator returns a structure capable of storing Responses about a
// deal and check if the deal is certified or not.
func NewEmptyAggregator(suite vss.Suite, verifiers []kyber.Point) *Aggregator {
	return &Aggregator{
		suite:     suite,
		verifiers: verifiers,
		responses: make(map[uint32]*vss.Response),
	}
}

var errDealAlreadyProcessed = errors.New("vss: verifier already received a deal")

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
	a.timeout = true
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

func (a *Aggregator) VerifyDeal(d *vss.Deal, inclusion bool) error {
	if a.deal != nil && inclusion {
		return errDealAlreadyProcessed

	}
	if a.deal == nil {
		a.commits = d.Commitments
		a.sid = d.SessionID
		a.deal = d
		a.t = int(d.T)
	}

	if !vss.ValidT(int(d.T), a.verifiers) {
		return errors.New("vss: invalid t received in Deal")
	}

	if int(d.T) != a.t {
		return errors.New("vss: incompatible threshold - potential attack")
	}

	if !bytes.Equal(a.sid, d.SessionID) {
		return errors.New("vss: find different sessionIDs from Deal")
	}

	fi := d.SecShare
	if fi.I >= uint32(len(a.verifiers)) {
		return errors.New("vss: index out of bounds in Deal")
	}
	// compute fi * G
	fig := a.suite.Point().Base().Mul(fi.V, nil)

	commitPoly := share.NewPubPoly(a.suite, nil, d.Commitments)

	pubShare := commitPoly.Eval(fi.I)
	if !fig.Equal(pubShare.V) {
		return errors.New("vss: share does not verify against commitments in Deal")
	}
	return nil
}

// SetThreshold is used to specify the expected threshold *before* the verifier
// receives anything. Sometimes, a verifier knows the treshold in advance and
// should make sure the one it receives from the dealer is consistent. If this
// method is not called, the first threshold received is considered as the
// "truth".
func (a *Aggregator) SetThreshold(t int) {
	a.t = t
}

// ProcessResponse verifies the validity of the given response and stores it
// internall. It is  the public version of VerifyResponse created this way to
// allow higher-level package to use these functionalities.
func (a *Aggregator) ProcessResponse(r *vss.Response) error {
	return a.VerifyResponse(r)
}

func (a *Aggregator) VerifyResponse(r *vss.Response) error {
	if a.sid != nil && !bytes.Equal(r.SessionID, a.sid) {
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
		// if one justification is bad, then flag the dealer as malicious
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

// DealCertified returns true if the deal is certified.
// For a deal to be certified, it needs to comply to the following
// conditions in two different cases, since we are not working with the
// synchrony assumptions from Feldman's VSS:
// Before the timeout (i.e. before the "period" ends):
// 1. there is at least t approvals
// 2. all complaints must be justified (a complaint becomes an approval when
// justified) -> no complaints
// 3. there must not be absent responses
// After the timeout, when the "period" ended, we replace the third condition:
// 3. there must not be more than n-t missing responses (otherwise it is not
// possible to retrieve the secret).
// If the caller previously called `SetTimeout` and `DealCertified()` returns
// false, the protocol MUST abort as the deal is not and never will be validated.
func (a *Aggregator) DealCertified() bool {
	var absentVerifiers int
	var approvals int
	var isComplaint bool

	for i := range a.verifiers {
		if r, ok := a.responses[uint32(i)]; !ok {
			absentVerifiers++
		} else if r.StatusApproved {
			approvals++
		} else {
			isComplaint = true
		}
	}
	enoughApprovals := approvals >= a.t
	tooMuchAbsents := absentVerifiers > len(a.verifiers)-a.t
	baseCondition := !a.badDealer && enoughApprovals && !isComplaint
	if a.timeout {
		return baseCondition && !tooMuchAbsents
	}
	return baseCondition && !(absentVerifiers > 0)
}

// MissingResponses returns the indexes of the expected but missing responses.
func (a *Aggregator) MissingResponses() []int {
	var absents []int
	for i := range a.verifiers {
		if _, ok := a.responses[uint32(i)]; !ok {
			absents = append(absents, i)
		}
	}
	return absents
}
