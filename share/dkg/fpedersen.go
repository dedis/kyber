package dkg

import (
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"

	"github.com/drand/kyber"
	"github.com/drand/kyber/encrypt/ecies"
	"github.com/drand/kyber/share"
	"github.com/drand/kyber/util/random"
)

type Suite interface {
	kyber.Group
	kyber.HashFactory
	kyber.XOFFactory
	kyber.Random
}

// Config holds all required information to run a fresh DKG protocol or a
// resharing protocol. In the case of a new fresh DKG protocol, one must fill
// the following fields: Suite, Longterm, NewNodes, Threshold (opt). In the case
// of a resharing protocol, one must fill the following: Suite, Longterm,
// OldNodes, NewNodes. If the node using this config is creating new shares
// (i.e. it belongs to the current group), the Share field must be filled in
// with the current share of the node. If the node using this config is a new
// addition and thus has no current share, the PublicCoeffs field be must be
// filled in.
type Config struct {
	Suite Suite

	// Longterm is the longterm secret key.
	Longterm kyber.Scalar

	// Current group of share holders. It will be nil for new DKG. These nodes
	// will have invalid shares after the protocol has been run. To be able to issue
	// new shares to a new group, the group member's public key must be inside this
	// list and in the Share field. Keys can be disjoint or not with respect to the
	// NewNodes list.
	OldNodes []Node

	// PublicCoeffs are the coefficients of the distributed polynomial needed
	// during the resharing protocol. The first coefficient is the key. It is
	// required for new share holders.  It should be nil for a new DKG.
	PublicCoeffs []kyber.Point

	// Expected new group of share holders. These public-key designated nodes
	// will be in possession of new shares after the protocol has been run. To be a
	// receiver of a new share, one's public key must be inside this list. Keys
	// can be disjoint or not with respect to the OldNodes list.
	NewNodes []Node

	// Share to refresh. It must be nil for a new node wishing to
	// join or create a group. To be able to issue new fresh shares to a new group,
	// one's share must be specified here, along with the public key inside the
	// OldNodes field.
	Share *DistKeyShare

	// The threshold to use in order to reconstruct the secret with the produced
	// shares. This threshold is with respect to the number of nodes in the
	// NewNodes list. If unspecified, default is set to
	// `vss.MinimumT(len(NewNodes))`. This threshold indicates the degree of the
	// polynomials used to create the shares, and the minimum number of
	// verification required for each deal.
	Threshold int

	// OldThreshold holds the threshold value that was used in the previous
	// configuration. This field MUST be specified when doing resharing, but is
	// not needed when doing a fresh DKG. This value is required to gather a
	// correct number of valid deals before creating the distributed key share.
	// NOTE: this field is always required (instead of taking the default when
	// absent) when doing a resharing to avoid a downgrade attack, where a resharing
	// the number of deals required is less than what it is supposed to be.
	OldThreshold int

	// Reader is an optional field that can hold a user-specified entropy source.
	// If it is set, Reader's data will be combined with random data from crypto/rand
	// to create a random stream which will pick the dkg's secret coefficient. Otherwise,
	// the random stream will only use crypto/rand's entropy.
	Reader io.Reader

	// When UserReaderOnly it set to true, only the user-specified entropy source
	// Reader will be used. This should only be used in tests, allowing reproducibility.
	UserReaderOnly bool

	// FastSync is a mode where nodes sends pre-emptively responses indicating
	// that the shares they received are good. If a share is invalid, a
	// complaint is still sent as usual. This has two consequences:
	//  - In the event all shares are good, nodes don't need to wait for the
	//  timeout; they can already finish the protocol at the point.
	//  - However, it requires nodes to send more messages on the network. We
	//  pass from a O(f) where f is the number of faults to a O(n^2). Note that
	//  the responses messages are small.
	FastSync bool
}

const (
	InitState = iota
	ShareState
	ResponseState
	JustifState
	FinishState
)

// DistKeyGenerator is the struct that runs the DKG protocol.
type DistKeyGenerator struct {
	// config driving the behavior of DistKeyGenerator
	c     *Config
	suite Suite

	long     kyber.Scalar
	pub      kyber.Point
	dpriv    *share.PriPoly
	dpub     *share.PubPoly
	statuses *StatusMatrix
	// the valid shares we received
	validShares map[uint32]kyber.Scalar
	// all public polynomials we have seen
	allPublics map[uint32]*share.PubPoly
	// list of dealers that clearly gave invalid deals / responses / justifs
	evicted []uint32
	state   int
	// index in the old list of nodes
	oidx int
	// index in the new list of nodes
	nidx int
	// old threshold used in the previous DKG
	oldT int
	// new threshold to use in this round
	newT int
	// indicates whether we are in the re-sharing protocol or basic DKG
	isResharing bool
	// indicates whether we are able to issue shares or not
	canIssue bool
	// Indicates whether we are able to receive a new share or not
	canReceive bool
	// indicates whether the node holding the pub key is present in the new list
	newPresent bool
	// indicates whether the node is present in the old list
	oldPresent bool
	// already processed our own deal
	processed bool
	// public polynomial of the old group
	olddpub *share.PubPoly
}

// NewDistKeyHandler takes a Config and returns a DistKeyGenerator that is able
// to drive the DKG or resharing protocol.
func NewDistKeyHandler(c *Config) (*DistKeyGenerator, error) {
	if c.NewNodes == nil && c.OldNodes == nil {
		return nil, errors.New("dkg: can't run with empty node list")
	}

	var isResharing bool
	if c.Share != nil || c.PublicCoeffs != nil {
		isResharing = true
	}
	if isResharing {
		if c.OldNodes == nil {
			return nil, errors.New("dkg: resharing config needs old nodes list")
		}
		if c.OldThreshold == 0 {
			return nil, errors.New("dkg: resharing case needs old threshold field")
		}
	}
	// canReceive is true by default since in the default DKG mode everyone
	// participates
	var canReceive = true
	pub := c.Suite.Point().Mul(c.Longterm, nil)
	oidx, oldPresent := findPub(c.OldNodes, pub)
	nidx, newPresent := findPub(c.NewNodes, pub)
	if !oldPresent && !newPresent {
		return nil, errors.New("dkg: public key not found in old list or new list")
	}

	var newThreshold int
	if c.Threshold != 0 {
		newThreshold = c.Threshold
	} else {
		newThreshold = MinimumT(len(c.NewNodes))
	}
	if !newPresent {
		// if we are not in the new list of nodes, then we definitely can't
		// receive anything
		canReceive = false
	}

	var err error
	var canIssue bool
	var secretCoeff kyber.Scalar
	var dpriv *share.PriPoly
	var dpub *share.PubPoly
	var olddpub *share.PubPoly
	var oldThreshold int
	if !isResharing && newPresent {
		// fresk DKG present
		randomStream := random.New()
		// if the user provided a reader, use it alone or combined with crypto/rand
		if c.Reader != nil && !c.UserReaderOnly {
			randomStream = random.New(c.Reader, rand.Reader)
		} else if c.Reader != nil && c.UserReaderOnly {
			randomStream = random.New(c.Reader)
		}
		pickErr := func() (err error) {
			defer func() {
				if r := recover(); r != nil {
					err = fmt.Errorf("error picking secret: %v", r)
					return
				}
			}()
			secretCoeff = c.Suite.Scalar().Pick(randomStream)
			return nil
		}()
		if pickErr != nil {
			return nil, pickErr
		}
		// in fresh dkg case, we consider the old nodes same a new nodes
		c.OldNodes = c.NewNodes
		oidx, oldPresent = findPub(c.OldNodes, pub)
		canIssue = true
	} else if c.Share != nil {
		// resharing case
		secretCoeff = c.Share.Share.V
		canIssue = true
	}
	dpriv = share.NewPriPoly(c.Suite, c.Threshold, secretCoeff, c.Suite.RandomStream())
	dpub = dpriv.Commit(c.Suite.Point().Base())
	// resharing case and we are included in the new list of nodes
	if isResharing && newPresent {
		if c.PublicCoeffs == nil && c.Share == nil {
			return nil, errors.New("dkg: can't receive new shares without the public polynomial")
		} else if c.PublicCoeffs != nil {
			olddpub = share.NewPubPoly(c.Suite, c.Suite.Point().Base(), c.PublicCoeffs)
		} else if c.Share != nil {
			// take the commits of the share, no need to duplicate information
			c.PublicCoeffs = c.Share.Commits
			olddpub = share.NewPubPoly(c.Suite, c.Suite.Point().Base(), c.PublicCoeffs)
		}
		// oldThreshold is only useful in the context of a new share holder, to
		// make sure there are enough correct deals from the old nodes.
		canReceive = true
		oldThreshold = len(c.PublicCoeffs)
	}
	var statuses *StatusMatrix
	if c.FastSync {
		// in fast sync mode, we set every shares to complaint by default and
		// expect everyone to send success for correct shares
		statuses = NewStatusMatrix(c.OldNodes, c.NewNodes, Complaint)
	} else {
		// in normal mode, every shares is expected to be correct, unless honest
		// nodes send a complaint
		statuses = NewStatusMatrix(c.OldNodes, c.NewNodes, Success)
	}
	dkg := &DistKeyGenerator{
		state:       InitState,
		suite:       c.Suite,
		long:        c.Longterm,
		pub:         pub,
		canReceive:  canReceive,
		canIssue:    canIssue,
		isResharing: isResharing,
		dpriv:       dpriv,
		dpub:        dpub,
		olddpub:     olddpub,
		oidx:        oidx,
		nidx:        nidx,
		c:           c,
		oldT:        oldThreshold,
		newT:        newThreshold,
		newPresent:  newPresent,
		oldPresent:  oldPresent,
		statuses:    statuses,
		validShares: make(map[uint32]kyber.Scalar),
		allPublics:  make(map[uint32]*share.PubPoly),
	}
	return dkg, err
}

func (d *DistKeyGenerator) Deals() (*DealBundle, error) {
	if !d.canIssue {
		return nil, fmt.Errorf("new members can't issue deals")
	}
	if d.state != InitState {
		return nil, fmt.Errorf("dkg not in the initial state, can't produce deals")
	}
	fmt.Printf("Deals() dkg %d:\n", d.nidx)
	deals := make([]Deal, 0, len(d.c.NewNodes))
	for _, node := range d.c.NewNodes {
		// compute share
		si := d.dpriv.Eval(int(node.Index)).V
		fmt.Printf("\t- sending to %d: %s\n", node.Index, si.String())
		if d.canReceive && uint32(d.nidx) == node.Index {
			d.validShares[node.Index] = si
			d.allPublics[node.Index] = d.dpub
			// we don't send our own share - useless
			continue
		}
		msg, _ := si.MarshalBinary()
		cipher, err := ecies.Encrypt(d.c.Suite, node.Public, msg, sha256.New)
		if err != nil {
			return nil, err
		}
		deals = append(deals, Deal{
			ShareIndex:     node.Index,
			EncryptedShare: cipher,
		})
	}
	d.state = ShareState
	return &DealBundle{
		DealerIndex: uint32(d.nidx),
		Deals:       deals,
		Public:      d.dpub,
	}, nil
}

func (d *DistKeyGenerator) ProcessDeals(bundles []*DealBundle) (*ResponseBundle, error) {
	if !d.canReceive {
		return nil, fmt.Errorf("this node is not in the new group: it should not process shares")
	}
	if d.canIssue && d.state != ShareState {
		// oldnode member is not in the right state
		return nil, fmt.Errorf("processdeals can only be called after producing shares")
	}
	if d.canReceive && !d.canIssue && d.state != InitState {
		// newnode member which is not in the old group is not in the riht state
		return nil, fmt.Errorf("processdeals can only be called once after creating the dkg for a new member")
	}
	fmt.Printf("ProcessDeals(): dkg %d:\n", d.nidx)
	seenIndex := make(map[uint32]bool)
	for _, bundle := range bundles {
		if d.canIssue && bundle.DealerIndex == uint32(d.oidx) {
			// dont look at our own deal
			continue
		}
		if !isIndexIncluded(d.c.OldNodes, bundle.DealerIndex) {
			continue
		}
		if bundle.Public == nil || bundle.Public.Threshold() != d.c.Threshold {
			// invalid public polynomial is clearly cheating
			// so we evict him from the list
			// since we assume broadcast channel, every honest player will evict
			// this party as well
			d.evicted = append(d.evicted, bundle.DealerIndex)
			continue
		}
		if seenIndex[bundle.DealerIndex] {
			// already saw a bundle from the same dealer - clear sign of
			// cheating so we evict him from the list
			d.evicted = append(d.evicted, bundle.DealerIndex)
			continue
		}
		seenIndex[bundle.DealerIndex] = true
		d.allPublics[bundle.DealerIndex] = bundle.Public
		for _, deal := range bundle.Deals {
			if !isIndexIncluded(d.c.NewNodes, deal.ShareIndex) {
				// invalid index for share holder is a clear sign of cheating
				// so we evict him from the list
				// and we don't even need to look at the rest
				d.evicted = append(d.evicted, bundle.DealerIndex)
				break
			}
			if deal.ShareIndex != uint32(d.nidx) {
				// we dont look at other's shares
				continue
			}
			shareBuff, err := ecies.Decrypt(d.c.Suite, d.long, deal.EncryptedShare, sha256.New)
			if err != nil {
				continue
			}
			share := d.c.Suite.Scalar()
			if err := share.UnmarshalBinary(shareBuff); err != nil {
				continue
			}
			// check if share is valid w.r.t. public commitment
			comm := bundle.Public.Eval(d.nidx).V
			commShare := d.c.Suite.Point().Mul(share, nil)
			if !comm.Equal(commShare) {
				// invalid share - will issue complaint
				continue
			}

			if d.isResharing {
				// check that the evaluation this public polynomial at 0,
				// corresponds to the commitment of the previous the dealer's index
				oldShareCommit := d.olddpub.Eval(int(bundle.DealerIndex)).V
				publicCommit := bundle.Public.Commit()
				if !oldShareCommit.Equal(publicCommit) {
					// inconsistent share from old member
					continue
				}
			}
			// share is valid -> store it
			d.statuses.Set(bundle.DealerIndex, deal.ShareIndex, true)
			d.validShares[bundle.DealerIndex] = share
			fmt.Printf("\t- storing share from %d : %d->%s\n", bundle.DealerIndex, deal.ShareIndex, share.String())
		}
	}
	if d.canIssue {
		// we mark our own status for our own share
		d.statuses.Set(uint32(d.nidx), uint32(d.nidx), true)
	}

	// we set to true the status of each node that are present in both list
	// for their respective index -> we assume the share a honest node creates is
	// correct for himself - that he won't create an invalid share for himself
	for _, dealer := range d.c.OldNodes {
		nidx, found := findPub(d.c.NewNodes, dealer.Public)
		if !found {
			continue
		}
		d.statuses.Set(dealer.Index, uint32(nidx), true)
	}

	// producing response part
	var responses []Response
	var myshares = d.statuses.StatusesForShare(uint32(d.nidx))
	for _, node := range d.c.OldNodes {
		// if the node is evicted, we don't even need to send a complaint or a
		// response response since every honest node evicts him as well.
		if d.isEvicted(node.Index) {
			continue
		}

		if myshares[node.Index] {
			if d.c.FastSync {
				// we send success responses as well
				responses = append(responses, Response{
					DealerIndex: node.Index,
					Status:      Success,
				})
			}
		} else {
			// dealer i did not give a successful share (or absent etc)
			responses = append(responses, Response{
				DealerIndex: uint32(node.Index),
				Status:      false,
			})
		}
	}
	var bundle *ResponseBundle
	if len(responses) > 0 {
		bundle = &ResponseBundle{
			ShareIndex: uint32(d.nidx),
			Responses:  responses,
		}
	}
	d.state = ResponseState
	fmt.Printf("dealer %d statuses: \n%s\n", d.nidx, d.statuses)
	return bundle, nil
}

func (d *DistKeyGenerator) ExpectedResponsesFastSync() int {
	return len(d.c.NewNodes)
}

func (d *DistKeyGenerator) ProcessResponses(bundles []*ResponseBundle) (*Result, *JustificationBundle, error) {
	// if we are a old node that will leave
	if !d.canReceive && d.state != ShareState {
		return nil, nil, fmt.Errorf("leaving node can process responses only after creating shares")
	} else if d.state != ResponseState {
		return nil, nil, fmt.Errorf("can only process responses after processing shares")
	}

	if !d.c.FastSync && len(bundles) == 0 && d.canReceive {
		// if we are not in fastsync, we expect only complaints
		// if there is no complaints all is good
		res, err := d.computeResult()
		return res, nil, err
	}

	var foundComplaint bool
	for _, bundle := range bundles {
		if d.canIssue && bundle.ShareIndex == uint32(d.oidx) {
			// just in case we dont treat our own response
			continue
		}
		if !isIndexIncluded(d.c.NewNodes, bundle.ShareIndex) {
			continue
		}

		for _, response := range bundle.Responses {
			if !isIndexIncluded(d.c.OldNodes, response.DealerIndex) {
				// the index of the dealer doesn't exist - clear violation
				// so we evict
				d.evicted = append(d.evicted, bundle.ShareIndex)
				continue
			}

			if !d.c.FastSync && response.Status == Success {
				// we should only receive complaint if we are not in fast sync
				// mode - clear violation
				// so we evict
				d.evicted = append(d.evicted, bundle.ShareIndex)
				continue
			}

			d.statuses.Set(response.DealerIndex, bundle.ShareIndex, response.Status)
			if response.Status == Complaint {
				foundComplaint = true
			}
		}
	}

	if !foundComplaint {
		// there is no complaint !
		if d.canReceive {
			res, err := d.computeResult()
			return res, nil, err
		} else {
			d.state = FinishState
			// old nodes that are not present in the new group
			return nil, nil, nil
		}
	}
	d.state = JustifState

	if !d.canIssue {
		// new node that is expecting some justifications
		return nil, nil, nil
	}

	// check if there are justifications this node needs to produce
	var myrow = d.statuses.StatusesOfDealer(uint32(d.oidx))
	var justifications []Justification
	var foundJustifs bool
	for shareIndex, status := range myrow {
		if status != Complaint {
			continue
		}
		// create justifications for the requested share
		var sh = d.dpriv.Eval(int(shareIndex)).V
		justifications = append(justifications, Justification{
			ShareIndex: shareIndex,
			Share:      sh,
		})
		foundJustifs = true
	}
	if !foundJustifs {
		// no justifications required from us !
		return nil, nil, nil
	}

	var bundle = JustificationBundle{
		DealerIndex:    uint32(d.oidx),
		Justifications: justifications,
	}
	return nil, &bundle, nil
}

func (d *DistKeyGenerator) ProcessJustifications(bundles []JustificationBundle) (*Result, error) {
	if !d.canReceive {
		return nil, fmt.Errorf("old eviceted node should not process justifications")
	}
	if d.state != JustifState {
		return nil, fmt.Errorf("node can only process justifications after processing responses")
	}

	seen := make(map[uint32]bool)
	for _, bundle := range bundles {
		if seen[bundle.DealerIndex] {
			// bundle contains duplicate - clear violation
			// so we evict
			d.evicted = append(d.evicted, bundle.DealerIndex)
			continue
		}
		if d.canIssue && bundle.DealerIndex == uint32(d.oidx) {
			// we dont treat our own justifications
			continue
		}
		if !isIndexIncluded(d.c.OldNodes, bundle.DealerIndex) {
			// index is invalid
			continue
		}
		if d.isEvicted(bundle.DealerIndex) {
			// already evicted node
			continue
		}
		seen[bundle.DealerIndex] = true
		for _, justif := range bundle.Justifications {
			if !isIndexIncluded(d.c.NewNodes, justif.ShareIndex) {
				// invalid index - clear violation
				// so we evict
				d.evicted = append(d.evicted, bundle.DealerIndex)
				continue
			}
			pubPoly, ok := d.allPublics[bundle.DealerIndex]
			if !ok {
				// dealer hasn't given any public polynomial at the first phase
				// so we evict directly - no need to look at its justifications
				d.evicted = append(d.evicted, bundle.DealerIndex)
				break
			}
			// compare commit and public poly
			commit := d.c.Suite.Point().Mul(justif.Share, nil)
			expected := pubPoly.Eval(int(justif.ShareIndex)).V
			if !commit.Equal(expected) {
				// invalid justification - evict
				d.evicted = append(d.evicted, bundle.DealerIndex)
				continue
			}
			if d.isResharing {
				// check that the evaluation this public polynomial at 0,
				// corresponds to the commitment of the previous the dealer's index
				oldShareCommit := d.olddpub.Eval(int(bundle.DealerIndex)).V
				publicCommit := pubPoly.Commit()
				if !oldShareCommit.Equal(publicCommit) {
					// inconsistent share from old member
					d.evicted = append(d.evicted, bundle.DealerIndex)
					continue
				}
			}
			// valid share -> mark OK
			d.statuses.Set(bundle.DealerIndex, justif.ShareIndex, true)
			if justif.ShareIndex == uint32(d.nidx) {
				// store the share if it's for us
				d.validShares[bundle.DealerIndex] = justif.Share
			}
		}
	}

	// check if there is enough dealer entries marked as all success
	var allGood int
	for _, n := range d.c.OldNodes {
		if d.isEvicted(n.Index) {
			continue
		}
		if !d.statuses.AllTrue(n.Index) {
			// this dealer has some unjustified shares
			continue
		}
		allGood++
	}
	if allGood < d.c.Threshold {
		// that should not happen in the threat model but we still returns the
		// fatal error here so DKG do not finish
		d.state = FinishState
		return nil, fmt.Errorf("only %d/%d valid deals - dkg abort", allGood, d.c.Threshold)
	}
	// otherwise it's all good - let's compute the result
	return d.computeResult()
}

func (d *DistKeyGenerator) computeResult() (*Result, error) {
	d.state = FinishState
	// add a full complaint row on the nodes that are evicted
	for _, index := range d.evicted {
		d.statuses.SetAll(index, false)
	}
	// add all the shares and public polynomials together for the deals that are
	// valid ( equivalently or all justified)
	if d.isResharing {
		// instead of adding, in this case, we interpolate all shares
		return d.computeResharingResult()
	} else {
		return d.computeDKGResult()
	}
}

func (d *DistKeyGenerator) computeResharingResult() (*Result, error) {
	// only old nodes sends shares
	shares := make([]*share.PriShare, len(d.c.OldNodes))
	coeffs := make([][]kyber.Point, len(d.c.OldNodes))
	var nodes []Node
	for _, n := range d.c.OldNodes {
		if !d.statuses.AllTrue(n.Index) {
			// this dealer has some unjustified shares
			continue
		}
		pub, ok := d.allPublics[n.Index]
		if !ok {
			return nil, fmt.Errorf("BUG:public polynomial not found from dealer %d", n.Index)
		}
		_, commitments := pub.Info()
		coeffs[n.Index] = commitments

		sh, ok := d.validShares[n.Index]
		if !ok {
			return nil, fmt.Errorf("BUG: %d private share not found from dealer %d", d.nidx, n.Index)
		}
		// share of dist. secret. Invertion of rows/column
		shares[n.Index] = &share.PriShare{
			V: sh,
			I: int(n.Index),
		}
		nodes = append(nodes, n)
	}

	// the private polynomial is generated from the old nodes, thus inheriting
	// the old threshold condition
	priPoly, err := share.RecoverPriPoly(d.suite, shares, d.oldT, len(d.c.OldNodes))
	if err != nil {
		return nil, err
	}
	privateShare := &share.PriShare{
		I: int(d.nidx),
		V: priPoly.Secret(),
	}

	// recover public polynomial by interpolating coefficient-wise all
	// polynomials
	// the new public polynomial must however have "newT" coefficients since it
	// will be held by the new nodes.
	finalCoeffs := make([]kyber.Point, d.newT)
	for i := 0; i < d.newT; i++ {
		tmpCoeffs := make([]*share.PubShare, len(coeffs))
		// take all i-th coefficients
		for j := range coeffs {
			if coeffs[j] == nil {
				continue
			}
			tmpCoeffs[j] = &share.PubShare{I: j, V: coeffs[j][i]}
		}

		// using the old threshold / length because there are at most
		// len(d.c.OldNodes) i-th coefficients since they are the one generating one
		// each, thus using the old threshold.
		coeff, err := share.RecoverCommit(d.suite, tmpCoeffs, d.oldT, len(d.c.OldNodes))
		if err != nil {
			return nil, err
		}
		finalCoeffs[i] = coeff
	}

	// Reconstruct the final public polynomial
	pubPoly := share.NewPubPoly(d.suite, nil, finalCoeffs)

	if !pubPoly.Check(privateShare) {
		return nil, errors.New("dkg: share do not correspond to public polynomial ><")
	}

	return &Result{
		QUAL: nodes,
		Key: &DistKeyShare{
			Commits: finalCoeffs,
			Share:   privateShare,
		},
	}, nil
}

func (d *DistKeyGenerator) computeDKGResult() (*Result, error) {
	finalShare := d.c.Suite.Scalar().Zero()
	var finalPub *share.PubPoly
	var nodes []Node
	fmt.Printf("ComputeDKG(): dkg %d:\n", d.nidx)
	for _, n := range d.c.OldNodes {
		if !d.statuses.AllTrue(n.Index) {
			// this dealer has some unjustified shares
			fmt.Println(" UNJUSTIFIED")
			continue
		}
		sh, ok := d.validShares[n.Index]
		if !ok {
			return nil, fmt.Errorf("BUG: private share not found from dealer %d", n.Index)
		}
		pub, ok := d.allPublics[n.Index]
		if !ok {
			return nil, fmt.Errorf("BUG: idx %d public polynomial not found from dealer %d", d.nidx, n.Index)
		}
		fmt.Printf("\t- Adding share from %d: %s\n", n.Index, sh.String())
		finalShare = finalShare.Add(finalShare, sh)
		if finalPub == nil {
			finalPub = pub
		} else {
			finalPub.Add(pub)
		}
		nodes = append(nodes, n)
	}
	_, commits := finalPub.Info()
	return &Result{
		QUAL: nodes,
		Key: &DistKeyShare{
			Commits: commits,
			Share: &share.PriShare{
				I: d.nidx,
				V: finalShare,
			},
		},
	}, nil
}

func findPub(list []Node, toFind kyber.Point) (int, bool) {
	for i, p := range list {
		if p.Public.Equal(toFind) {
			return i, true
		}
	}
	return 0, false
}

func MinimumT(n int) int {
	return (n + 1) / 2
}

func validT(t int, verifiers []kyber.Point) bool {
	return t >= 2 && t <= len(verifiers) && int(uint32(t)) == t
}

func isIndexIncluded(list []Node, index uint32) bool {
	for _, n := range list {
		if n.Index == index {
			return true
		}
	}
	return false
}

func (d *DistKeyGenerator) isEvicted(node uint32) bool {
	for _, idx := range d.evicted {
		if node == idx {
			return true
		}
	}
	return false
}
