// Package dkg implements the protocol described in "A threshold cryptosystem without a trusted party"
// by Torben Pryds Pedersen. https://dl.acm.org/citation.cfm?id=1754929.
package dkg

import (
	"errors"

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

	// Expected new group of share holders. These public-key designated nodes
	// will be in possession of new shares after the protocol is ran. To be a
	// receiver a of new share, one's public key must be inside this list. Keys
	// can be disjoint or not with respect to the OldNodes list.
	NewNodes []kyber.Point

	// Current group of share holders. It can be nil for new DKG. These nodes
	// will have invalid share after the protocol is ran. To be able to issue
	// new fresh shares to a new group, one's public key must be inside this
	// list alongside with the Share field. Keys can be disjoint or not with
	// respect to the NewNodes list.
	OldNodes []kyber.Point

	// DistPublic is the distributed public key required during the resharing
	// protocol. It is required for new share holders. It can be nil for new DKG.
	DistPublic kyber.Point

	// Share to refresh. Can be nil for new DKG or new node wishing to join the
	// group. To be able to issue new fresh shares to a new group, one's share
	// must be specified here, along with the public key inside the OldNodes
	// field.
	Share *DistKeyShare

	// New threshold to use if set. Default will be returned by `vss.MinimumT()`
	Threshold int
}

func NewDKGConfig(suite Suite, longterm kyber.Scalar, participants []kyber.Point) *Config {
	return &Config{
		Suite:    suite,
		Longterm: longterm,
		NewNodes: participants,
	}
}

// NewReshareConfig returns a new config to use with DistKeyGenerator to run the
// re-sharing protocols between the old nodes and the new nodes,i.e. the future
// share holders. Share must be non-nil for previously enrolled nodes to
// actively issue new shares. Dpublic is needed for a participant in then
// newNodes list to verify the validity of the new received shares.
func NewReshareConfig(suite Suite, longterm kyber.Scalar, oldNodes, newNodes []kyber.Point,
	share *DistKeyShare, dpublic kyber.Point) *Config {
	return &Config{
		Suite:      suite,
		Longterm:   longterm,
		OldNodes:   oldNodes,
		NewNodes:   newNodes,
		Share:      share,
		DistPublic: dpublic,
	}
}

// DistKeyGenerator is the struct that runs the DKG protocol.
type DistKeyGenerator struct {
	suite Suite

	long kyber.Scalar
	pub  kyber.Point

	participants []kyber.Point

	t int

	dealer *vss.Dealer
	// verifiers indexed by dealer index
	verifiers map[uint32]*vss.Verifier

	// index in the old list of nodes
	oidx int
	// index in the new list of nodes
	nidx int
	// indicates whether we are able to issue shares or not
	canIssue bool
	// indicates whether we are in the re-sharing protocol or basic DKG
	isResharing bool
	// commitments of the shares of the old polynomial
	oldShareCommits []*PubShare
}

func NewDistKeyHandler(c *Config) (*DistKeyGenerator, error) {
	if c.NewNodes == nil && c.OldNodes == nil {
		return nil, errors.New("dkg: can't run with empty node list")
	} else if c.NewNodes == nil && c.OldNodes != nil {
		return nil, errors.New("dkg: can't run with old nodes but without new nodes")
	}

	var isResharing bool
	if c.OldNodes != nil {
		// if there are new nodes specified we are the resharing mode
		isResharing = true
	}

	pub := suite.Point().Mul(longterm, nil)
	oidx, oldPresent := findPub(c.OldNodes)
	nidx, newPresent := findPub(c.NewNodes)
	if !oldPresent && !newPresent {
		return nil, errors.New("dkg: public key not found in old list or new list")
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
		secretCoeff = c.Share.V
	} else {
		ownSecret := c.Suite.Scalar().Pick(c.Suite.RandomStream())
	}

	var threshold int
	if c.Treshold != 0 {
		threshold = c.Threshold
	} else {
		threshold = vss.MinimumT(len(c.NewNodes))
	}

	dealer, err := vss.NewDealer(suite, c.Longterm, secretCoeff, c.NewNodes, threshold)
	if err != nil {
		return nil, err
	}

	return &DistKeyGenerator{
		dealer:       dealer,
		verifiers:    make(map[uint32]*vss.Verifier),
		t:            threshold,
		suite:        c.Suite,
		long:         c.Longterm,
		pub:          pub,
		participants: participants,
		canIssue:     canIssue,
		isResharing:  isResharing,
	}, nil
}

// initDistKeyGenerator returns a dist key generator with the given secret as
// the first coefficient of the polynomial of this dealer.
func initDistKeyGenerator(suite Suite, longterm kyber.Scalar, participants []kyber.Point, t int, secret kyber.Scalar) (*DistKeyGenerator, error) {
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
	ownSec := secret
	dealer, err := vss.NewDealer(suite, longterm, ownSec, participants, t)
	if err != nil {
		return nil, err
	}

	return &DistKeyGenerator{
		dealer:    dealer,
		verifiers: make(map[uint32]*vss.Verifier),
		t:         t,
		suite:     suite,
		long:      longterm,
		pub:       pub,
		index:     index,
		oindex:    int(index),
		canIssue:  true,
		config: &Config{
			Suite:    suite,
			Longterm: long,
			NewNodes: participants,
		},
	}, nil
}

// NewDistKeyGenerator returns a DistKeyGenerator out of the suite, the longterm
// secret key, the list of participants, the threshold t parameter and a given
// secret. It returns an error if the secret key's commitment can't be found in
// the list of participants.
func NewDistKeyGenerator(suite Suite, longterm kyber.Scalar, participants []kyber.Point, t int) (*DistKeyGenerator, error) {
	ownSecret := suite.Scalar().Pick(suite.RandomStream())
	return initDistKeyGenerator(suite, longterm, participants, t, ownSecret)
}

// NewDistKeyGeneratorWithoutSecret simply returns a DistKeyGenerator with an
// nil secret.  It is used to renew the private shares without affecting the
// secret.
func NewDistKeyGeneratorWithoutSecret(suite Suite, longterm kyber.Scalar, participants []kyber.Point, t int) (*DistKeyGenerator, error) {
	ownSecret := suite.Scalar().Zero()
	return initDistKeyGenerator(suite, longterm, participants, t, ownSecret)
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
	var shareCommits []*PubShare
	if d.isResharing {
		// create share commitments of the polynomial to embed in the deals
		commits := d.c.Share.Commits
		poly := NewPubPoly(d.suite, d.suite.Point().Base(), commits)
		shareCommits = poly.Shares(len(d.c.OldNodes))
	}

	dd := make(map[int]*Deal)
	for i := range d.c.NewNodes {
		distd := &Deal{
			Index:        d.index,
			Deal:         deals[i],
			ShareCommits: shareCommits,
		}
		if d.isResharing {
			// embeds the share commitments
			distd.ShareCommits = shareCommits
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

		if i == int(d.index) {
			if _, ok := d.verifiers[d.index]; ok {
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
		// XXX Check if the dealer is also in the new list, and then set the
		// complaint
		//d.verifiers[dd.Index].UnsafeSetResponseDKG(dd.Index, vss.StatusComplaint)
		d.verifiers[dd.Index].UnsafeSetResponseDKG(d.nidx, vss.StatusComplaint)
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

	if d.isResharing {
		// verify share integrity wrt to the dist. secret
		// 1. check that the commitment of the share is the same as the one received
		// in the ShareCommitments field.
		dealCommits := v.Commits()
		if !dealCommits[0].Equal(dd.ShareCommits[dd.Index].V) {
			return reject()
		}
		// 2. check that the interpolation of all share commitments leads to dist
		// public key
		recovered, err := share.RecoverCommit(d.suite, dd.ShareCommits, d.c.Threshold, len(d.c.OldNodes))
		if err != nil {
			return reject()
		}
		if !publicKey.Equal(d.c.DistPublic) {
			return reject()
		}

		// save it for later
		// XXX Make sure all sharecommits received are the same and not an
		// attacker defined slice
		d.oldShareCommits = dd.ShareCommits
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

	if resp.Index != uint32(d.index) {
		return nil, nil
	}

	var j *Justification

	if d.canIssue {
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
	}

	// XXX Check for justification part in the resharing protocol ?

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
			I: int(d.index),
			V: sh,
		},
		PrivatePoly: d.dealer.PrivatePoly().Coefficients(),
	}, nil

}

func (d *DistKeyGenerator) resharingKey() (*DistKeyShare, error) {
	shares := make([]*PriShare, 0, len(d.NewNodes))
	d.qualIter(func(i uint32, v *vss.Verifier) bool {
		// share of dist. secret
		deal := v.Deal()
		deal.SecShare.I = int(i)
		shares = append(shares, deal.SecShare)
		return true
	})

	if err != nil {
		return nil, err
	}
	_, commits := pub.Info()

	return &DistKeyShare{
		Commits: commits,
		Share: &share.PriShare{
			I: int(d.index),
			V: sh,
		},
		PrivatePoly: d.dealer.PrivatePoly().Coefficients(),
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
