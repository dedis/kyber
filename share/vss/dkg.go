package vss

import (
	"crypto/cipher"
	"errors"

	"github.com/dedis/crypto/abstract"
)

type DistKeyShare struct {

	// the public key generated
	Public abstract.Point

	// share of the distributed secret
	Share abstract.Scalar

	// index of the participant holding this share
	Index int
}

// DistDeal is a simple wrapper around Deal used to provide the index of the
// Dealer together with its Deal.
// NOTE: Doing that in vss.go would be possible but then the Dealer is always
// assumed to be a member of the participants..
type DistDeal struct {
	Index uint32

	Deal *Deal
}

type DistKeyGenerator struct {
	suite abstract.Suite

	index int
	long  abstract.Scalar
	pub   abstract.Point

	participants []abstract.Point

	t int

	dealer    *Dealer
	verifiers map[string]*Verifier
}

func NewDistKeyGeneration(suite abstract.Suite, longterm abstract.Secret, participants []abstract.Point, r cipher.Stream, t int) (*DistKeyGenerator, error) {
	d := new(DistKeyGenerator)
	pub := suite.Point().Mul(nil, longterm)
	// find our index
	var found bool
	for i, p := range participants {
		if p.Equal(pub) {
			found = true
			d.index = i
			break
		}
	}
	if !found {
		return nil, errors.New("dkg: own public key not found in list of participants")
	}
	// generate our dealer / deal
	ownSec := suite.Scalar().Pick(r)
	d.dealer, err = NewDealer(suite, longterm, ownSec, participants, r, t)
	if err != nil {
		return nil, err
	}
	// to receive the other deals
	d.verifiers = make(map[string]*Verifier)
	d.t = t
	d.suite = suite
	d.long = longterm
	d.pub = pub
	d.participants = participants
	return r, nil
}

// DistDeals returns all the DistDeal that must be broadcasted to every
// participants. The DistDeal corresponding to this DKG is already added
// to this DKG and is ommitted from the returned slice. To know
// to which one to give the DistDeal, simply look the "Index" field.
func (d *DistKeyGenerator) DistDeal() []*DistDeal {
	deals := d.dealer.Deals()
	dd := make([]*DistDeal, len(deals))
	for i, deal := range deals {
		distd := &DistDeal{
			Index: d.index,
			Deal:  deal,
		}
		if i == d.index {
			d.ProcessDistDeal(distd)
		}
	}
	return dd
}

func (d *DistKeyGenerator) ProcessDistDeal(dd *DistDeal) (*Approval, *Complaint, error) {
	pub, ok := findPub(d.participants, dd.Index)
	if !ok {
		return nil, nil, errors.New("dkg: dist deal out of bounds index")
	}
	if _, ok := d.verifiers[dd.Deal.SessionID]; ok {
		return nil, nil, errors.New("dkg: already received dist deal from same index")
	}

	ver, err := NewVerifier(d.suite, d.long, pub, d.participants)
	if err != nil {
		return nil, nil, err
	}

	d.verifiers[string(dd.Deal.SessionID)] = ver
	return ver.ProcessDeal(dd.Deal)
}

func (d *DistKeyGenerator) ProcessApproval(ap *Approval) error {
	if v, ok := d.verifiers[ap.SessionID]; !ok {
		return errors.New("dkg: approval received but no deal for it")
	} else {
		return v.ProcessApproval(ap)
	}
}

func (d *DistKeyGenerator) ProcessComplaint(cp *Complaint) (*Justification, error) {
	if cp.Index == uint32(d.index) {
		return d.dealer.ProcessComplaint(cp)
	}
	if v, ok := d.verifiers[cp.SessionID]; !ok {
		return errors.New("dkg: complaint received but no deal for it")
	} else {
		return nil, v.ProcessComplaint(cp)
	}
}

func (d *DistKeyGenerator) ProcessJustification(j *Justification) error {
	if v, ok := d.verifiers[j.Deal.SessionID]; !ok {
		return nil, errors.New("dkg: Justification received but no deal for it")
	} else {
		return v.ProcessJustification(j)
	}
}

func (d *DistKeyGenerator) Done() bool {
	for _, v := range d.verifiers {
		if !(v.EnoughApprovals() && v.DealCertified()) {
			return false
		}
	}
	return true
}

// ProduceSharedSecret will generate the sharedsecret relative to this receiver
// it will throw an error if something is wrong such as not enough Dealers received
// The shared secret can be computed when all deals have been sent and
// basically consists of a
// 1. Public Polynomial which is basically the sums of all Dealers's polynomial
// 2. Share of the global Private Polynomial (which is to never be computed directly), which is
// 		basically SUM of fj(i) for a receiver i
func (r *Receiver) DistKeyShare() (*DistKeyShare, error) {
	if len(r.deals) < 1 {
		return nil, errors.New("Receiver has 0 Dealers in its data.Can't produce SharedSecret.")
	}
	pub := new(PubPoly)
	pub.InitNull(r.suite, r.info.T, r.suite.Point().Base())
	share := r.suite.Scalar().Zero()
	for index := range r.deals {
		// Compute secret shares of the shared secret = sum of the respectives shares of peer i
		// For peer i , s = SUM fj(i)
		s := r.deals[index].RevealShare(r.index, r.key)
		//s, e := r.Dealers[index].State.RevealShare(r.index, r.Key)
		share.Add(share, s)

		// Compute shared public polynomial = SUM of indiviual public polynomials
		pub.Add(pub, r.deals[index].PubPoly())
	}

	if val := pub.Check(r.index, share); val == false {
		return nil, errors.New("Receiver's secret share of the shared secret could not be checked against the shared polynomial")
	}

	return &SharedSecret{
		Pub:   pub,
		Share: &share,
		Index: r.index,
	}, nil
}

// MARSHALLING side

// PolyInfo marshalling :
func (p *Threshold) Equal(p2 Threshold) bool {
	return p.N == p2.N && p.R == p2.R && p.T == p2.T
}
