// Package dkg implements the protocol described in "A threshold cryptosystem without a trusted party"
// by Torben Pryds Pedersen. https://dl.acm.org/citation.cfm?id=1754929.
package dkg

import (
	"errors"
	"fmt"

	"github.com/dedis/kyber"

	"github.com/dedis/kyber/share"
	vss "github.com/dedis/kyber/share/vss/pedersen"
	"github.com/dedis/kyber/sign/schnorr"
)

// Suite wraps the functionalities needed by the dkg package
type Suite vss.Suite

type Config struct {
	Suite Suite

	// Longterm is the longterm secret key.
	Longterm kyber.Scalar

	// Current group of share holders. It can be nil for new DKG. These nodes
	// will have invalid share after the protocol is ran. To be able to issue
	// new fresh shares to a new group, one's public key must be inside this
	// list alongside with the Share field. Keys can be disjoint or not with
	// respect to the NewNodes list.
	OldNodes []kyber.Point

	// PublicCoeffs are the coefficients of the distributed polynomial needed
	// during the resharing protocol. The first coefficient is the key.It is
	// required for new share holders.  It can be nil for new DKG.
	PublicCoeffs []kyber.Point

	// Expected new group of share holders. These public-key designated nodes
	// will be in possession of new shares after the protocol is ran. To be a
	// receiver a of new share, one's public key must be inside this list. Keys
	// can be disjoint or not with respect to the OldNodes list.
	NewNodes []kyber.Point

	// Share to refresh. It must be nil for fresh DKG or new node wishing to
	// join the group. To be able to issue new fresh shares to a new group,
	// one's share must be specified here, along with the public key inside the
	// OldNodes field.
	Share *DistKeyShare

	// New threshold to use if set. Default will be returned by `vss.MinimumT()`
	Threshold int
}

func NewDKGConfig(suite Suite, longterm kyber.Scalar, participants []kyber.Point) *Config {
	return &Config{
		Suite:     suite,
		Longterm:  longterm,
		NewNodes:  participants,
		Threshold: vss.MinimumT(len(participants)),
	}
}

// NewReshareConfig returns a new config to use with DistKeyGenerator to run the
// re-sharing protocols between the old nodes and the new nodes,i.e. the future
// share holders. Share must be non-nil for previously enrolled nodes to
// actively issue new shares. Dpublic is needed for a participant in then
// newNodes list to verify the validity of the new received shares.
func NewReshareConfig(suite Suite, longterm kyber.Scalar, oldNodes, newNodes []kyber.Point,
	share *DistKeyShare, pcoeffs []kyber.Point) *Config {
	return &Config{
		Suite:        suite,
		Longterm:     longterm,
		OldNodes:     oldNodes,
		NewNodes:     newNodes,
		Share:        share,
		PublicCoeffs: pcoeffs,
		Threshold:    vss.MinimumT(len(newNodes)),
	}
}

// DistKeyGenerator is the struct that runs the DKG protocol.
type DistKeyGenerator struct {
	// config driving the behavior of DistKeyGenerator
	c     *Config
	suite Suite

	long   kyber.Scalar
	pub    kyber.Point
	dpub   *share.PubPoly
	t      int
	dealer *vss.Dealer
	// verifiers indexed by dealer index
	verifiers map[uint32]*vss.Verifier

	// index in the old list of nodes
	oidx int
	// index in the new list of nodes
	nidx int
	// indicates whether we are in the re-sharing protocol or basic DKG
	isResharing bool
	// indicates whether we are able to issue shares or not
	canIssue bool
	// Indicates whether we are able to receive a new share or not
	canReceive bool
	// commitments of the shares of the old polynomial
	oldShareCommits []*share.PubShare
}

func NewDistKeyHandler(c *Config) (*DistKeyGenerator, error) {
	if c.NewNodes == nil && c.OldNodes == nil {
		return nil, errors.New("dkg: can't run with empty node list")
	} else if c.NewNodes == nil && c.OldNodes != nil {
		return nil, errors.New("dkg: can't run with old nodes but without new nodes")
	}

	// canReceive is true by default since in the default DKG mode everyone
	// participates
	var canReceive bool = true
	var isResharing bool
	if c.Share != nil || c.PublicCoeffs != nil {
		isResharing = true
	}

	pub := c.Suite.Point().Mul(c.Longterm, nil)
	oidx, oldPresent := findPub(c.OldNodes, pub)
	nidx, newPresent := findPub(c.NewNodes, pub)
	if !oldPresent && !newPresent {
		return nil, errors.New("dkg: public key not found in old list or new list")
	}

	var dpub *share.PubPoly
	if !newPresent {
		// if we are not in the new list of nodes, then we definitely can't
		// receive anything
		canReceive = false
	} else if isResharing && newPresent && c.PublicCoeffs == nil {
		return nil, errors.New("dkg: can't receive new shares without the public polynomial")
	} else {
		// there are old nodes, new nodes, public coefficients and we are
		// present in the new list => we can receive shares
		canReceive = true
		dpub = share.NewPubPoly(c.Suite, c.Suite.Point().Base(), c.PublicCoeffs)
	}

	var canIssue bool
	if oldPresent && c.Share != nil {
		// if we are present in the old list and there is a share given in the
		// config, we can issue new shares with the resharing protocol
		canIssue = true
	} else if newPresent && c.Share == nil {
		// if we are present in the new list and there's no share, we start a
		// new DKG from scratch
		canIssue = true
	}

	var secretCoeff kyber.Scalar
	if c.Share != nil {
		secretCoeff = c.Share.Share.V
	} else {
		secretCoeff = c.Suite.Scalar().Pick(c.Suite.RandomStream())
	}

	var threshold int
	if c.Threshold != 0 {
		threshold = c.Threshold
	} else {
		threshold = vss.MinimumT(len(c.NewNodes))
	}

	dealer, err := vss.NewDealer(c.Suite, c.Longterm, secretCoeff, c.NewNodes, threshold)
	if err != nil {
		return nil, err
	}

	return &DistKeyGenerator{
		dealer:      dealer,
		verifiers:   make(map[uint32]*vss.Verifier),
		t:           threshold,
		suite:       c.Suite,
		long:        c.Longterm,
		pub:         pub,
		canIssue:    canIssue,
		canReceive:  canReceive,
		isResharing: isResharing,
		dpub:        dpub,
		oidx:        oidx,
		nidx:        nidx,
		c:           c,
	}, nil
}

// NewDistKeyGenerator returns a dist key generator ready to create a new
// distributed key.
func NewDistKeyGenerator(suite Suite, longterm kyber.Scalar, participants []kyber.Point, t int) (*DistKeyGenerator, error) {
	c := &Config{
		Suite:     suite,
		Longterm:  longterm,
		NewNodes:  participants,
		OldNodes:  participants,
		Threshold: t,
	}
	return NewDistKeyHandler(c)
}

// Deals returns all the deals that must be broadcasted to all
// participants. The deal corresponding to this DKG is already added
// to this DKG and is ommitted from the returned map. To know which
// participant a deal belongs to, loop over the keys as indices in the
// list of participants:
//
//   for i,dd := range distDeals {
//      sendTo(participants[i],dd)
//   }
//
// If this method cannot process its own Deal, that indicates a
// sever problem with the configuration or implementation and
// results in a panic.
func (d *DistKeyGenerator) Deals() (map[int]*Deal, error) {
	if !d.canIssue {
		return nil, errors.New("dkg: can't issue deals with this DKG. Check config.")
	}
	deals, err := d.dealer.EncryptedDeals()
	if err != nil {
		return nil, err
	}
	dd := make(map[int]*Deal)
	for i := range d.c.NewNodes {
		distd := &Deal{
			Index: uint32(d.oidx),
			Deal:  deals[i],
		}
		// sign the deal
		buff, err := distd.MarshalBinary()
		if err != nil {
			return nil, err
		}
		distd.Signature, err = schnorr.Sign(d.suite, d.long, buff)
		if err != nil {
			return nil, err
		}

		if i == int(d.nidx) {
			if _, ok := d.verifiers[uint32(d.nidx)]; ok {
				// already processed our own deal
				continue
			}
			if resp, err := d.ProcessDeal(distd); err != nil {
				panic("dkg: cannot process own deal: " + err.Error())
			} else if resp.Response.Status != vss.StatusApproval {
				panic("dkg: own deal gave a complaint")
			}
			continue
		}
		dd[i] = distd
	}
	return dd, nil
}

// ProcessDeal takes a Deal created by Deals() and stores and verifies it. It
// returns a Response to broadcast to every other participant. It returns an
// error in case the deal has already been stored, or if the deal is incorrect
// (see vss.Verifier.ProcessEncryptedDeal).
func (d *DistKeyGenerator) ProcessDeal(dd *Deal) (*Response, error) {
	// public key of the dealer
	pub, ok := getPub(d.c.OldNodes, dd.Index)
	if !ok {
		return nil, errors.New("dkg: dist deal out of bounds index")
	}

	// verify signature
	buff, err := dd.MarshalBinary()
	if err != nil {
		return nil, err
	}
	if err := schnorr.Verify(d.suite, pub, buff, dd.Signature); err != nil {
		return nil, err
	}

	if _, ok := d.verifiers[dd.Index]; ok {
		return nil, errors.New("dkg: already received dist deal from same index")
	}

	// verifier receiving the dealer's deal
	ver, err := vss.NewVerifier(d.suite, d.long, pub, d.c.NewNodes)
	if err != nil {
		return nil, err
	}

	d.verifiers[dd.Index] = ver
	resp, err := ver.ProcessEncryptedDeal(dd.Deal)
	if err != nil {
		return nil, err
	}

	reject := func() (*Response, error) {
		idx, present := findPub(d.c.NewNodes, pub)
		if present {
			d.verifiers[uint32(idx)].UnsafeSetResponseDKG(uint32(idx), vss.StatusComplaint)
		}
		// indicate to VSS that the new status is complaint, since the check is
		// done outdone VSS package control.
		d.verifiers[uint32(d.nidx)].UnsafeSetResponseDKG(uint32(d.nidx), vss.StatusComplaint)
		resp.Status = vss.StatusComplaint
		s, err := schnorr.Sign(d.suite, d.long, resp.Hash(d.suite))
		if err != nil {
			return nil, err
		}
		resp.Signature = s
		return &Response{
			Index:    dd.Index,
			Response: resp,
		}, nil
	}

	if d.isResharing && d.canReceive {
		// verify share integrity wrt to the dist. secret
		dealCommits := ver.Commits()
		// Check that the received committed share is equal to the one we
		// generate from the known public polynomial
		expectedPubShare := d.dpub.Eval(int(dd.Index))
		if !expectedPubShare.V.Equal(dealCommits[0]) {
			return reject()
		}
	} else {
		// Set StatusApproval for the verifier that represents the participant
		// that distibuted the Deal
		d.verifiers[dd.Index].UnsafeSetResponseDKG(dd.Index, vss.StatusApproval)
	}

	return &Response{
		Index:    dd.Index,
		Response: resp,
	}, nil
}

// ProcessResponse takes a response from every other peer.  If the response
// designates the deal of another participant than this dkg, this dkg stores it
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

	if !d.canIssue {
		return nil, nil
	}

	if d.canIssue && resp.Index != uint32(d.oidx) {
		return nil, nil
	}

	j, err := d.dealer.ProcessResponse(resp.Response)
	if err != nil {
		return nil, err
	}
	if j == nil {
		return nil, nil
	}
	if err := v.ProcessJustification(j); err != nil {
		return nil, err
	}

	return &Justification{
		Index:         uint32(d.oidx),
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
	return len(d.QUAL()) >= len(d.c.NewNodes)
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

// DistKeyShare generates the distributed key relative to this receiver.
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
	if !d.canReceive {
		return nil, errors.New("dkg: should not expect to compute any dist. share")
	}

	if d.isResharing {
		return d.resharingKey()
	}

	return d.dkgKey()
}

func (d *DistKeyGenerator) dkgKey() (*DistKeyShare, error) {
	sh := d.suite.Scalar().Zero()
	var pub *share.PubPoly
	var err error

	d.qualIter(func(i uint32, v *vss.Verifier) bool {
		// share of dist. secret = sum of all share received.
		deal := v.Deal()
		s := deal.SecShare.V
		sh = sh.Add(sh, s)
		// Dist. public key = sum of all revealed commitments
		poly := share.NewPubPoly(d.suite, d.suite.Point().Base(), deal.Commitments)
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
			I: int(d.nidx),
			V: sh,
		},
		PrivatePoly: d.dealer.PrivatePoly().Coefficients(),
	}, nil

}

func (d *DistKeyGenerator) resharingKey() (*DistKeyShare, error) {
	// only old nodes sends shares
	shares := make([]*share.PriShare, 0, len(d.c.OldNodes))
	coeffs := make(map[int][]kyber.Point)
	d.qualIter(func(i uint32, v *vss.Verifier) bool {
		// share of dist. secret
		deal := v.Deal()
		deal.SecShare.I = int(i)
		shares = append(shares, deal.SecShare)
		coeffs[int(i)] = deal.Commitments
		return true
	})

	// recover private share (with the rest of the polynomial)
	priPoly, err := share.RecoverPriPoly(d.suite, shares, d.t, len(d.c.NewNodes))
	if err != nil {
		return nil, err
	}

	// recover public polynomial by interpolating coefficient-wise all
	// polynomials
	finalCoeffs := make([]kyber.Point, d.t)
	for i := 0; i < d.t; i++ {
		tmpCoeffs := make([]*share.PubShare, 0, len(coeffs))
		// take all i-th coefficients
		for j, coeffs := range coeffs {
			tmpCoeffs = append(tmpCoeffs, &share.PubShare{I: j, V: coeffs[i]})
		}
		// recover the i-th public coefficient
		coeff, err := share.RecoverCommit(d.suite, tmpCoeffs, d.t, len(d.c.OldNodes))
		if err != nil {
			return nil, fmt.Errorf("dkg: can't recover public coefficients %s", err)
		}
		finalCoeffs[i] = coeff
	}
	// Reconstruct the final public polynomial
	pubPoly := share.NewPubPoly(d.suite, d.suite.Point().Base(), finalCoeffs)
	share := &share.PriShare{
		I: int(d.nidx),
		V: priPoly.Secret(),
	}

	if !pubPoly.Check(share) {
		return nil, errors.New("dkg: share do not correspond to public polynomial ><")
	}
	return &DistKeyShare{
		Commits:     finalCoeffs,
		Share:       share,
		PrivatePoly: priPoly.Coefficients(),
	}, nil

}

//Renew adds the new distributed key share g (with secret 0) to the distributed key share d.
func (d *DistKeyShare) Renew(suite Suite, g *DistKeyShare) (*DistKeyShare, error) {
	//Check G(0) = 0*G.
	if !g.Public().Equal(suite.Point().Base().Mul(suite.Scalar().Zero(), nil)) {
		return nil, errors.New("wrong renewal function")
	}

	//Check whether they have the same index
	if d.Share.I != g.Share.I {
		return nil, errors.New("not the same party")
	}

	newShare := suite.Scalar().Add(d.Share.V, g.Share.V)
	newCommits := make([]kyber.Point, len(d.Commits))
	for i := range newCommits {
		newCommits[i] = suite.Point().Add(d.Commits[i], g.Commits[i])
	}
	return &DistKeyShare{
		Commits: newCommits,
		Share: &share.PriShare{
			I: d.Share.I,
			V: newShare,
		},
	}, nil
}

func getPub(list []kyber.Point, i uint32) (kyber.Point, bool) {
	if i >= uint32(len(list)) {
		return nil, false
	}
	return list[i], true
}

func findPub(list []kyber.Point, toFind kyber.Point) (int, bool) {
	for i, p := range list {
		if p.Equal(toFind) {
			return i, true
		}
	}
	return 0, false
}

func checksDealCertified(i uint32, v *vss.Verifier) bool {
	return v.DealCertified()
}
