package dkg

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"

	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/kyber/v3/encrypt/ecies"
	"go.dedis.ch/kyber/v3/share"
	"go.dedis.ch/kyber/v3/sign"
	"go.dedis.ch/kyber/v3/util/random"
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

	// Reader is an optional field that can hold a user-specified entropy
	// source.  If it is set, Reader's data will be combined with random data
	// from crypto/rand to create a random stream which will pick the dkg's
	// secret coefficient. Otherwise, the random stream will only use
	// crypto/rand's entropy.
	Reader io.Reader

	// When UserReaderOnly is set to true, only the user-specified entropy
	// source Reader will be used. This should only be used in tests, allowing
	// reproducibility.
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

	// Nonce is required to avoid replay attacks from previous runs of a DKG /
	// resharing. The required property of the Nonce is that it must be unique
	// accross runs. A Nonce must be of length 32 bytes. User can get a secure
	// nonce by calling `GetNonce()`.
	Nonce []byte

	// Auth is the scheme to use to authentify the packets sent and received
	// during the protocol.
	Auth sign.Scheme

	// Log enables the DKG logic and protocol to log important events (mostly
	// errors).  from participants. Errors don't mean the protocol should be
	// stopped, so logging is the best way to communicate information to the
	// application layer. It can be nil.
	Log Logger
}

// Phase is a type that represents the different stages of the DKG protocol.
type Phase int

const (
	InitPhase Phase = iota
	DealPhase
	ResponsePhase
	JustifPhase
	FinishPhase
)

func (p Phase) String() string {
	switch p {
	case InitPhase:
		return "init"
	case DealPhase:
		return "deal"
	case ResponsePhase:
		return "response"
	case JustifPhase:
		return "justification"
	case FinishPhase:
		return "finished"
	default:
		return "unknown"
	}
}

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
	// list of share holders that misbehaved during the response phase
	evictedHolders []Index
	state          Phase
	// index in the old list of nodes
	oidx Index
	// index in the new list of nodes
	nidx Index
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
	if len(c.NewNodes) == 0 && len(c.OldNodes) == 0 {
		return nil, errors.New("dkg: can't run with empty node list")
	}
	if len(c.Nonce) != NonceLength {
		return nil, errors.New("dkg: invalid nonce length")
	}
	if c.Auth == nil {
		return nil, errors.New("dkg: need authentication scheme")
	}

	var isResharing bool
	if c.Share != nil || c.PublicCoeffs != nil {
		isResharing = true
	}
	if isResharing {
		if len(c.OldNodes) == 0 {
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
	if err := c.CheckForDuplicates(); err != nil {
		return nil, err
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
		// in normal mode, every shares of other nodes is expected to be
		// correct, unless honest nodes send a complaint
		statuses = NewStatusMatrix(c.OldNodes, c.NewNodes, Success)
		if canReceive {
			// we set the statuses of the shares we expect to receive as complaint
			// by default, so if we miss one share or there's an invalid share,
			// it'll generate a complaint
			for _, node := range c.OldNodes {
				statuses.Set(node.Index, uint32(nidx), Complaint)
			}
		}
	}
	dkg := &DistKeyGenerator{
		state:       InitPhase,
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
	if d.state != InitPhase {
		return nil, fmt.Errorf("dkg not in the initial state, can't produce deals: %d", d.state)
	}
	deals := make([]Deal, 0, len(d.c.NewNodes))
	for _, node := range d.c.NewNodes {
		// compute share
		si := d.dpriv.Eval(int(node.Index)).V

		if d.canReceive && uint32(d.nidx) == node.Index {
			d.validShares[d.oidx] = si
			d.allPublics[d.oidx] = d.dpub
			// we set our own share as true, because we are not malicious!
			d.statuses.Set(d.oidx, d.nidx, Success)
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
	d.state = DealPhase
	_, commits := d.dpub.Info()
	bundle := &DealBundle{
		DealerIndex: uint32(d.oidx),
		Deals:       deals,
		Public:      commits,
		SessionID:   d.c.Nonce,
	}
	var err error
	bundle.Signature, err = d.sign(bundle)
	return bundle, err
}

// ProcessDeals process the deals from all the nodes. Each deal for this node is
// decrypted and stored. It returns a response bundle if there is any invalid or
// missing deals. It returns an error if the node is not in the right state, or
// if there is not enough valid shares, i.e. the dkg is failing already.
func (d *DistKeyGenerator) ProcessDeals(bundles []*DealBundle) (*ResponseBundle, error) {

	if d.canIssue && d.state != DealPhase {
		// oldnode member is not in the right state
		return nil, fmt.Errorf("processdeals can only be called after producing shares - state %s", d.state.String())
	}
	if d.canReceive && !d.canIssue && d.state != InitPhase {
		// newnode member which is not in the old group is not in the riht state
		return nil, fmt.Errorf("processdeals can only be called once after creating the dkg for a new member - state %s", d.state.String())
	}
	if !d.canReceive {
		// a node that is only in the old group should not process deals
		d.state = ResponsePhase // he moves on to the next phase silently
		return nil, nil
	}

	seenIndex := make(map[uint32]bool)
	for _, bundle := range bundles {
		if bundle == nil {
			d.c.Error("found nil Deal bundle")
			continue
		}
		if d.canIssue && bundle.DealerIndex == uint32(d.oidx) {
			// dont look at our own deal
			// Note that's why we are not checking if we are evicted at the end of this function and return an error
			// because we're supposing we are honest and we don't look at our own deal
			continue
		}
		if !isIndexIncluded(d.c.OldNodes, bundle.DealerIndex) {
			d.c.Error(fmt.Sprintf("dealer %d not in OldNodes", bundle.DealerIndex))
			continue
		}

		if bytes.Compare(bundle.SessionID, d.c.Nonce) != 0 {
			d.evicted = append(d.evicted, bundle.DealerIndex)
			d.c.Error("Deal with invalid session ID")
			continue
		}

		if bundle.Public == nil || len(bundle.Public) != d.c.Threshold {
			// invalid public polynomial is clearly cheating
			// so we evict him from the list
			// since we assume broadcast channel, every honest player will evict
			// this party as well
			d.evicted = append(d.evicted, bundle.DealerIndex)
			d.c.Error("Deal with nil public key or invalid threshold")
			continue
		}
		pubPoly := share.NewPubPoly(d.c.Suite, d.c.Suite.Point().Base(), bundle.Public)
		if seenIndex[bundle.DealerIndex] {
			// already saw a bundle from the same dealer - clear sign of
			// cheating so we evict him from the list
			d.evicted = append(d.evicted, bundle.DealerIndex)
			d.c.Error("Deal bundle already seen")
			continue
		}
		seenIndex[bundle.DealerIndex] = true
		d.allPublics[bundle.DealerIndex] = pubPoly
		for _, deal := range bundle.Deals {
			if !isIndexIncluded(d.c.NewNodes, deal.ShareIndex) {
				// invalid index for share holder is a clear sign of cheating
				// so we evict him from the list
				// and we don't even need to look at the rest
				d.evicted = append(d.evicted, bundle.DealerIndex)
				d.c.Error("Deal share holder evicted normally")
				break
			}
			if deal.ShareIndex != uint32(d.nidx) {
				// we dont look at other's shares
				continue
			}
			shareBuff, err := ecies.Decrypt(d.c.Suite, d.long, deal.EncryptedShare, sha256.New)
			if err != nil {
				d.c.Error("Deal share decryption invalid")
				continue
			}
			share := d.c.Suite.Scalar()
			if err := share.UnmarshalBinary(shareBuff); err != nil {
				d.c.Error("Deal share unmarshalling invalid")
				continue
			}
			// check if share is valid w.r.t. public commitment
			comm := pubPoly.Eval(int(d.nidx)).V
			commShare := d.c.Suite.Point().Mul(share, nil)
			if !comm.Equal(commShare) {
				d.c.Error("Deal share invalid wrt public poly")
				// invalid share - will issue complaint
				continue
			}

			if d.isResharing {
				// check that the evaluation this public polynomial at 0,
				// corresponds to the commitment of the previous the dealer's index
				oldShareCommit := d.olddpub.Eval(int(bundle.DealerIndex)).V
				publicCommit := pubPoly.Commit()
				if !oldShareCommit.Equal(publicCommit) {
					// inconsistent share from old member
					continue
				}
			}
			// share is valid -> store it
			d.statuses.Set(bundle.DealerIndex, deal.ShareIndex, true)
			d.validShares[bundle.DealerIndex] = share
			d.c.Info("Valid deal processed received from dealer", bundle.DealerIndex)
		}
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
		// XXX Is that always true ? Should we send a complaint still ?
		if contains(d.evicted, node.Index) {
			continue
		}

		if myshares[node.Index] {
			if d.c.FastSync {
				// we send success responses only in fast sync
				responses = append(responses, Response{
					DealerIndex: node.Index,
					Status:      Success,
				})
			}
		} else {
			// dealer i did not give a successful share (or absent etc)
			responses = append(responses, Response{
				DealerIndex: uint32(node.Index),
				Status:      Complaint,
			})
			d.c.Info(fmt.Sprintf("Complaint towards node %d", node.Index))
		}
	}
	var bundle *ResponseBundle
	if len(responses) > 0 {
		bundle = &ResponseBundle{
			ShareIndex: uint32(d.nidx),
			Responses:  responses,
			SessionID:  d.c.Nonce,
		}
		sig, err := d.sign(bundle)
		if err != nil {
			return nil, err
		}
		bundle.Signature = sig
	}
	d.state = ResponsePhase
	d.c.Info(fmt.Sprintf("sending back %d responses", len(responses)))
	return bundle, nil
}

func (d *DistKeyGenerator) ExpectedResponsesFastSync() int {
	return len(d.c.NewNodes)
}

// ProcessResponses takes the response from all nodes if any and returns a
// triplet:
// - the result if there is no complaint. If not nil, the DKG is finished.
// - the justification bundle if this node must produce at least one. If nil,
// this node must still wait on the justification phase.
// - error if the dkg must stop now, an unrecoverable failure.
func (d *DistKeyGenerator) ProcessResponses(bundles []*ResponseBundle) (res *Result, jb *JustificationBundle, err error) {
	if !d.canReceive && d.state != DealPhase {
		// if we are a old node that will leave
		return nil, nil, fmt.Errorf("leaving node can process responses only after creating shares")
	} else if d.state != ResponsePhase {
		return nil, nil, fmt.Errorf("can only process responses after processing shares - current state %s", d.state)
	}

	defer func() {
		if err == nil {
			err = d.checkIfEvicted(ResponsePhase)
		}
	}()

	if !d.c.FastSync && len(bundles) == 0 && d.canReceive && d.statuses.CompleteSuccess() {
		// if we are not in fastsync, we expect only complaints
		// if there is no complaints all is good
		res, err = d.computeResult()
		return
	}

	var validAuthors []Index
	var foundComplaint bool
	for _, bundle := range bundles {
		if bundle == nil {
			continue
		}
		if d.canIssue && bundle.ShareIndex == uint32(d.nidx) {
			// just in case we dont treat our own response
			continue
		}
		if !isIndexIncluded(d.c.NewNodes, bundle.ShareIndex) {
			d.c.Error("Response author already evicted")
			continue
		}

		if bytes.Compare(bundle.SessionID, d.c.Nonce) != 0 {
			d.c.Error("Response invalid session ID")
			d.evictedHolders = append(d.evictedHolders, bundle.ShareIndex)
			continue
		}

		for _, response := range bundle.Responses {
			if !isIndexIncluded(d.c.OldNodes, response.DealerIndex) {
				// the index of the dealer doesn't exist - clear violation
				// so we evict
				d.evictedHolders = append(d.evictedHolders, bundle.ShareIndex)
				d.c.Error("Response dealer index already evicted")
				continue
			}

			if !d.c.FastSync && response.Status == Success {
				// we should only receive complaint if we are not in fast sync
				// mode - clear violation
				// so we evict
				d.evictedHolders = append(d.evictedHolders, bundle.ShareIndex)
				d.c.Error("Response success but in regular mode")
				continue
			}

			d.statuses.Set(response.DealerIndex, bundle.ShareIndex, response.Status)
			if response.Status == Complaint {
				foundComplaint = true
			}
			validAuthors = append(validAuthors, bundle.ShareIndex)
		}
	}

	// In case of fast sync, we want to make sure all share holders have sent a
	// valid response (success or complaint). All share holders that did not
	// will be evicted from the final group. Since we are using a broadcast
	// channel, if a node is honest, its response will be received by all honest
	// nodes.
	if d.c.FastSync {
		// we only need to look at the nodes that did not sent any response,
		// since the invalid one are already markes as evicted
		allSent := append(validAuthors, d.evictedHolders...)
		for _, n := range d.c.NewNodes {
			if d.canReceive && d.nidx == n.Index {
				continue // we dont evict ourself
			}
			if !contains(allSent, n.Index) {
				d.c.Error(fmt.Sprintf("Response not seen from node %d (eviction)", n.Index))
				d.evictedHolders = append(d.evictedHolders, n.Index)
			}
		}
	}

	// there is no complaint in the responses received and the status matrix
	// is all filled with success that means we can finish the protocol -
	// regardless of the mode chosen (fast sync or not).
	if !foundComplaint && d.statuses.CompleteSuccess() {
		d.c.Info("msg", "DKG successful")
		d.state = FinishPhase
		if d.canReceive {
			res, err := d.computeResult()
			return res, nil, err
		} else {
			// old nodes that are not present in the new group
			return nil, nil, nil
		}
	}

	// check if there are some node who received at least t complaints.
	// In that case, they must be evicted already since their polynomial can
	// now be reconstructed so any observer can sign in its place.
	for _, n := range d.c.OldNodes {
		complaints := d.statuses.StatusesOfDealer(n.Index).LengthComplaints()
		if complaints >= d.c.Threshold {
			d.evicted = append(d.evicted, n.Index)
			d.c.Error(fmt.Sprintf("Response phase eviction of node %d", n.Index))
		}
	}

	d.state = JustifPhase

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
		d.c.Info(fmt.Sprintf("Producing justifications for node %d", shareIndex))
		foundJustifs = true
		// mark those shares as resolved in the statuses
		d.statuses.Set(uint32(d.oidx), shareIndex, true)
	}
	if !foundJustifs {
		// no justifications required from us !
		return nil, nil, nil
	}

	var bundle = &JustificationBundle{
		DealerIndex:    uint32(d.oidx),
		Justifications: justifications,
		SessionID:      d.c.Nonce,
	}

	signature, err := d.sign(bundle)
	if err != nil {
		return nil, nil, err
	}
	bundle.Signature = signature
	d.c.Info(fmt.Sprintf("%d justifications returned", len(justifications)))
	return nil, bundle, nil
}

// ProcessJustifications takes the justifications of the nodes and returns the
// results if there is enough QUALified nodes, or an error otherwise. Note that
// this method returns "nil,nil" if this node is a node only present in the old
// group of the dkg: indeed a node leaving the group don't need to process
// justifications, and can simply leave the protocol.
func (d *DistKeyGenerator) ProcessJustifications(bundles []*JustificationBundle) (*Result, error) {
	if !d.canReceive {
		// an old node leaving the group do not need to process justifications.
		// Here we simply return nil to avoid requiring higher level library to
		// think about which node should receive which packet
		return nil, nil
	}
	if d.state != JustifPhase {
		return nil, fmt.Errorf("node can only process justifications after processing responses - current state %s", d.state.String())
	}

	seen := make(map[uint32]bool)
	for _, bundle := range bundles {
		if bundle == nil {
			continue
		}
		if seen[bundle.DealerIndex] {
			// bundle contains duplicate - clear violation
			// so we evict
			d.evicted = append(d.evicted, bundle.DealerIndex)
			d.c.Error("Justification bundle contains duplicate - evicting dealer", bundle.DealerIndex)
			continue
		}
		if d.canIssue && bundle.DealerIndex == uint32(d.oidx) {
			// we dont treat our own justifications
			d.c.Info("Skipping own justification", true)
			continue
		}
		if !isIndexIncluded(d.c.OldNodes, bundle.DealerIndex) {
			// index is invalid
			d.c.Error("Invalid index - evicting dealer", bundle.DealerIndex)
			continue
		}
		if contains(d.evicted, bundle.DealerIndex) {
			// already evicted node
			d.c.Error("Already evicted dealer - evicting dealer", bundle.DealerIndex)
			continue
		}
		if bytes.Compare(bundle.SessionID, d.c.Nonce) != 0 {
			d.evicted = append(d.evicted, bundle.DealerIndex)
			d.c.Error("Justification bundle contains invalid session ID - evicting dealer", bundle.DealerIndex)
			continue
		}
		d.c.Info("ProcessJustifications - basic sanity checks done", true)

		seen[bundle.DealerIndex] = true
		for _, justif := range bundle.Justifications {
			if !isIndexIncluded(d.c.NewNodes, justif.ShareIndex) {
				// invalid index - clear violation
				// so we evict
				d.evicted = append(d.evicted, bundle.DealerIndex)
				d.c.Error("Invalid index in justifications - evicting dealer", bundle.DealerIndex)
				continue
			}
			pubPoly, ok := d.allPublics[bundle.DealerIndex]
			if !ok {
				// dealer hasn't given any public polynomial at the first phase
				// so we evict directly - no need to look at its justifications
				d.evicted = append(d.evicted, bundle.DealerIndex)
				d.c.Error("Public polynomial missing - evicting dealer", bundle.DealerIndex)
				break
			}
			// compare commit and public poly
			commit := d.c.Suite.Point().Mul(justif.Share, nil)
			expected := pubPoly.Eval(int(justif.ShareIndex)).V
			if !commit.Equal(expected) {
				// invalid justification - evict
				d.evicted = append(d.evicted, bundle.DealerIndex)
				d.c.Error("New share commit invalid - evicting dealer", bundle.DealerIndex)
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

					d.c.Error("Old share commit not equal to public commit - evicting dealer", bundle.DealerIndex)
					continue
				}
				d.c.Info("Old share commit and public commit valid", true)
			}
			// valid share -> mark OK
			d.statuses.Set(bundle.DealerIndex, justif.ShareIndex, true)
			if justif.ShareIndex == uint32(d.nidx) {
				// store the share if it's for us
				d.c.Info("Saving our key share for", justif.ShareIndex)
				d.validShares[bundle.DealerIndex] = justif.Share
			}
		}
	}

	// check if we are evicted or not
	if err := d.checkIfEvicted(JustifPhase); err != nil {
		return nil, fmt.Errorf("evicted at justification: %w", err)
	}

	// check if there is enough dealer entries marked as all success
	var allGood int
	for _, n := range d.c.OldNodes {
		if contains(d.evicted, n.Index) {
			continue
		}
		if !d.statuses.AllTrue(n.Index) {
			// this dealer has some unjustified shares
			continue
		}
		allGood++
	}
	targetThreshold := d.c.Threshold
	if d.isResharing {
		// we need enough old QUAL dealers, more than the threshold the old
		// group uses
		targetThreshold = d.c.OldThreshold
	}
	if allGood < targetThreshold {
		// that should not happen in the threat model but we still returns the
		// fatal error here so DKG do not finish
		d.state = FinishPhase
		return nil, fmt.Errorf("process-justifications: only %d/%d valid deals - dkg abort", allGood, targetThreshold)
	}

	// otherwise it's all good - let's compute the result
	return d.computeResult()
}

func (d *DistKeyGenerator) computeResult() (*Result, error) {
	d.state = FinishPhase
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
	shares := make([]*share.PriShare, 0, len(d.c.OldNodes))
	coeffs := make(map[Index][]kyber.Point, len(d.c.OldNodes))
	var validDealers []Index
	for _, n := range d.c.OldNodes {
		if !d.statuses.AllTrue(n.Index) {
			// this dealer has some unjustified shares
			// no need to check for th e evicted list since the status matrix
			// has been set previously to complaint for those
			continue
		}
		pub, ok := d.allPublics[n.Index]
		if !ok {
			return nil, fmt.Errorf("BUG: nidx %d: public polynomial not found from dealer %d", d.nidx, n.Index)
		}
		_, commitments := pub.Info()
		coeffs[n.Index] = commitments

		sh, ok := d.validShares[n.Index]
		if !ok {
			return nil, fmt.Errorf("BUG: nidx %d private share not found from dealer %d", d.nidx, n.Index)
		}
		// share of dist. secret. Invertion of rows/column
		shares = append(shares, &share.PriShare{
			V: sh,
			I: int(n.Index),
		})
		validDealers = append(validDealers, n.Index)
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
		tmpCoeffs := make([]*share.PubShare, 0, len(coeffs))
		// take all i-th coefficients
		for j := range coeffs {
			if coeffs[j] == nil {
				continue
			}
			tmpCoeffs = append(tmpCoeffs, &share.PubShare{I: int(j), V: coeffs[j][i]})
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

	// To compute the QUAL in the resharing case, we take each new nodes whose
	// column in the status matrix contains true for all valid dealers.
	// That means:
	// 1. we only look for valid deals
	// 2. we only take new nodes, i.e. new participants, that correctly ran the
	// protocol (i.e. absent nodes will not be counted)
	var qual []Node
	for _, newNode := range d.c.NewNodes {
		var invalid bool
		// look if this node is also a dealer which have been misbehaving
		for _, oldNode := range d.c.OldNodes {
			if d.statuses.AllTrue(oldNode.Index) {
				// it's a valid dealer as well
				continue
			}
			if oldNode.Public.Equal(newNode.Public) {
				// it's an invalid dealer, so we evict him
				invalid = true
				break
			}
		}
		// we also check if he has been misbehaving during the response phase
		// only
		if !invalid && !contains(d.evictedHolders, newNode.Index) {
			qual = append(qual, newNode)
		}
	}

	if len(qual) < d.c.Threshold {
		return nil, fmt.Errorf("dkg: too many uncompliant new participants %d/%d", len(qual), d.c.Threshold)
	}
	return &Result{
		QUAL: qual,
		Key: &DistKeyShare{
			Commits: finalCoeffs,
			Share:   privateShare,
		},
	}, nil
}

func (d *DistKeyGenerator) computeDKGResult() (*Result, error) {
	finalShare := d.c.Suite.Scalar().Zero()
	var err error
	var finalPub *share.PubPoly
	var nodes []Node
	for _, n := range d.c.OldNodes {
		if !d.statuses.AllTrue(n.Index) {
			// this dealer has some unjustified shares
			// no need to check the evicted list since the status matrix
			// has been set previously to complaint for those
			continue
		}

		// however we do need to check for evicted share holders since in this
		// case (DKG) both are the same.
		if contains(d.evictedHolders, n.Index) {
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
		finalShare = finalShare.Add(finalShare, sh)
		if finalPub == nil {
			finalPub = pub
		} else {
			finalPub, err = finalPub.Add(pub)
			if err != nil {
				return nil, err
			}
		}
		nodes = append(nodes, n)
	}
	if finalPub == nil {
		return nil, fmt.Errorf("BUG: final public polynomial is nil")
	}
	_, commits := finalPub.Info()
	return &Result{
		QUAL: nodes,
		Key: &DistKeyShare{
			Commits: commits,
			Share: &share.PriShare{
				I: int(d.nidx),
				V: finalShare,
			},
		},
	}, nil
}

var ErrEvicted = errors.New("our node is evicted from list of qualified participants")

// checkIfEvicted returns an error if this node is in one of the two eviction list. This is useful to detect
// our own misbehaviour or lack of connectivity: for example if this node can receive messages from others but is
// not able to send, everyone will send a complaint about this node, and thus it is going to be evicted.
// This method checks if you are and returns an error from the DKG to stop it. Once evicted a node's messages are
// not processed anymore and it is left out of the protocol.
func (d *DistKeyGenerator) checkIfEvicted(phase Phase) error {
	var arr []Index
	var indexToUse Index

	// For DKG -> for all phases look at evicted dealers since both lists are the same anyway
	// For resharing ->  only at response phase we evict some new share holders
	// 			otherwise, it's only dealers we evict (since deal and justif are made by dealers)
	if d.isResharing && phase == ResponsePhase {
		if !d.canReceive {
			// we can't be evicted as an old node leaving the group here
			return nil
		}
		arr = d.evictedHolders
		indexToUse = d.nidx
	} else {
		if !d.canIssue {
			// we can't be evicted as a new node in this setting
			return nil
		}
		arr = d.evicted
		indexToUse = d.oidx
	}
	for _, idx := range arr {
		if indexToUse == idx {
			return ErrEvicted
		}
	}
	return nil
}

func findPub(list []Node, toFind kyber.Point) (Index, bool) {
	for _, n := range list {
		if n.Public.Equal(toFind) {
			return n.Index, true
		}
	}
	return 0, false
}

func findIndex(list []Node, index Index) (kyber.Point, bool) {
	for _, n := range list {
		if n.Index == index {
			return n.Public, true
		}
	}
	return nil, false
}

func MinimumT(n int) int {
	return (n >> 1) + 1
}

func isIndexIncluded(list []Node, index uint32) bool {
	for _, n := range list {
		if n.Index == index {
			return true
		}
	}
	return false
}

func contains(nodes []Index, node Index) bool {
	for _, idx := range nodes {
		if node == idx {
			return true
		}
	}
	return false
}

// NonceLength is the length of the nonce
const NonceLength = 32

// GetNonce returns a suitable nonce to feed in the DKG config.
func GetNonce() []byte {
	var nonce [NonceLength]byte
	n, err := rand.Read(nonce[:])
	if n != NonceLength {
		panic("could not read enough random bytes for nonce")
	}
	if err != nil {
		panic(err)
	}
	return nonce[:]
}

func (d *DistKeyGenerator) sign(p Packet) ([]byte, error) {
	msg := p.Hash()
	priv := d.c.Longterm
	return d.c.Auth.Sign(priv, msg)
}

func (d *DistKeyGenerator) Info(keyvals ...interface{}) {
	d.c.Info(append([]interface{}{"generator"}, keyvals...))
}

func (d *DistKeyGenerator) Error(keyvals ...interface{}) {
	d.c.Info(append([]interface{}{"generator"}, keyvals...))
}

func (c *Config) Info(keyvals ...interface{}) {
	if c.Log != nil {
		c.Log.Info(append([]interface{}{"dkg-log"}, keyvals...))
	}
}

func (c *Config) Error(keyvals ...interface{}) {
	if c.Log != nil {
		c.Log.Error(append([]interface{}{"dkg-log"}, keyvals...))
	}
}

// CheckForDuplicates looks at the lits of node indices in the OldNodes and
// NewNodes list. It returns an error if there is a duplicate in either list.
// NOTE: It only looks at indices because it is plausible that one party may
// have multiple indices for the protocol, i.e. a higher "weight".
func (c *Config) CheckForDuplicates() error {
	checkDuplicate := func(list []Node) error {
		hashSet := make(map[Index]bool)
		for _, n := range list {
			if _, present := hashSet[n.Index]; present {
				return fmt.Errorf("index %d", n.Index)
			} else {
				hashSet[n.Index] = true
			}
		}
		return nil
	}
	if err := checkDuplicate(c.OldNodes); err != nil {
		return fmt.Errorf("found duplicate in old nodes list: %v", err)
	}
	if err := checkDuplicate(c.NewNodes); err != nil {
		return fmt.Errorf("found duplicate in new nodes list: %v", err)
	}
	return nil
}
