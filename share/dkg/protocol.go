package dkg

import (
	"bytes"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/drand/kyber"
	"github.com/drand/kyber/sign"
)

// Board is the interface between the dkg protocol and the external world. It
// consists in pushing packets out to other nodes and receiving in packets from
// the other nodes. A common board would use the network as the underlying
// communication mechanism but one can also use a smart contract based
// approach.
type Board interface {
	PushDeals(AuthDealBundle)
	IncomingDeal() <-chan AuthDealBundle
	PushResponses(AuthResponseBundle)
	IncomingResponse() <-chan AuthResponseBundle
	PushJustifications(AuthJustifBundle)
	IncomingJustification() <-chan AuthJustifBundle
}

// Phaser must signal on its channel when the protocol should move to a next
// phase. Phase must be sequential: DealPhase (start), ResponsePhase,
// JustifPhase and then FinishPhase.
// Note that if the dkg protocol finishes before the phaser sends the
// FinishPhase, the protocol will not listen on the channel anymore. This can
// happen if there is no complaints, or if using the "FastSync" mode.
// Most of the times, user should use the TimePhaser when using the network, but
// if one wants to use a smart contract as a board, then the phaser can tick at
// certain blocks, or when the smart contract tells it.
type Phaser interface {
	NextPhase() chan Phase
}

// TimePhaser is a phaser that sleeps between the different phases and send the
// signal over its channel.
type TimePhaser struct {
	out   chan Phase
	sleep func(Phase)
}

func NewTimePhaser(p time.Duration) *TimePhaser {
	return NewTimePhaserFunc(func(Phase) { time.Sleep(p) })
}

func NewTimePhaserFunc(sleepPeriod func(Phase)) *TimePhaser {
	return &TimePhaser{
		out:   make(chan Phase, 4),
		sleep: sleepPeriod,
	}
}

func (t *TimePhaser) Start() {
	t.out <- DealPhase
	t.sleep(DealPhase)
	t.out <- ResponsePhase
	t.sleep(ResponsePhase)
	t.out <- JustifPhase
	t.sleep(JustifPhase)
	t.out <- FinishPhase
}

func (t *TimePhaser) NextPhase() chan Phase {
	return t.out
}

// Protocol contains the logic to run a DKG protocol over a generic broadcast
// channel, called Board. It handles the receival of packets, ordering of the
// phases and the termination. A protocol can be ran over a network, a smart
// contract, or anything else that is implemented via the Board interface.
type Protocol struct {
	board    Board
	phaser   Phaser
	dkg      *DistKeyGenerator
	conf     *Config
	canIssue bool
	res      chan OptionResult
}

// Config is the configuration to give to a Protocol. It currently only embeds
// the dkg config and the authentication scheme. It is meant to be extensible
// and will probably contains more options to log and control the behavior of
// the protocol.
type Config struct {
	DkgConfig
	// Auth is the scheme to use to verify authentication of the packets
	// received from the board. If nil, authentication is not checked.
	Auth sign.Scheme
}

// XXX TO DELETE
func printNodes(list []Node) string {
	var arr []string
	for _, node := range list {
		arr = append(arr, fmt.Sprintf("[%d : %s]", node.Index, node.Public))
	}
	return strings.Join(arr, "\n")
}

func NewProtocol(c *Config, b Board, phaser Phaser) (*Protocol, error) {
	dkg, err := NewDistKeyHandler(&c.DkgConfig)
	if err != nil {
		return nil, err
	}
	// fast sync must only be enabled if there is an authentication scheme
	if c.DkgConfig.FastSync && c.Auth == nil {
		return nil, errors.New("fast sync only allowed with authentication enabled")
	}
	pub := c.DkgConfig.Suite.Point().Mul(c.DkgConfig.Longterm, nil)
	fmt.Printf("OLD NODES (idx %d) - pub %s:\n %s\nNEW NODES (idx %d):\n%s\n", dkg.oidx, pub, printNodes(c.DkgConfig.OldNodes), dkg.nidx, printNodes(c.DkgConfig.NewNodes))
	p := &Protocol{
		board:    b,
		phaser:   phaser,
		dkg:      dkg,
		conf:     c,
		canIssue: dkg.canIssue,
		res:      make(chan OptionResult, 1),
	}
	go p.Start()
	return p, nil
}

func (p *Protocol) Start() {
	var fastSync = p.conf.DkgConfig.FastSync
	if fastSync {
		p.startFast()
		return
	}
	var deals []*DealBundle
	var resps []*ResponseBundle
	var justifs []*JustificationBundle
	for {
		select {
		case newPhase := <-p.phaser.NextPhase():
			switch newPhase {
			case DealPhase:
				if !p.sendDeals() {
					return
				}
			case ResponsePhase:
				if !p.sendResponses(deals) {
					return
				}
			case JustifPhase:
				if !p.sendJustifications(resps) {
					return
				}
			case FinishPhase:
				p.finish(justifs)
				return
			}
		case newDeal := <-p.board.IncomingDeal():
			if err := p.VerifySignature(newDeal); err == nil {
				deals = append(deals, newDeal.Bundle)
			}
		case newResp := <-p.board.IncomingResponse():
			if err := p.VerifySignature(newResp); err == nil {
				resps = append(resps, newResp.Bundle)
			}
		case newJust := <-p.board.IncomingJustification():
			if err := p.VerifySignature(newJust); err == nil {
				justifs = append(justifs, newJust.Bundle)
			}
		}
	}
}

func (p *Protocol) startFast() {
	var deals = make(map[uint32]*DealBundle)
	var resps = make(map[uint32]*ResponseBundle)
	var justifs = make(map[uint32]*JustificationBundle)
	var newN = len(p.conf.DkgConfig.NewNodes)
	var oldN = len(p.conf.DkgConfig.OldNodes)
	var phase Phase
	sendResponseFn := func() bool {
		if phase != DealPhase {
			fmt.Printf("silently ignoring response phase since already done")
			return true
		}
		phase = ResponsePhase
		bdeals := make([]*DealBundle, 0, len(deals))
		for _, d := range deals {
			bdeals = append(bdeals, d)
		}
		fmt.Printf("proto %d - done sending responses\n", p.dkg.nidx)
		if !p.sendResponses(bdeals) {
			return false
		}
		return true
	}
	sendJustifFn := func() bool {
		if phase != ResponsePhase {
			return true
		}
		phase = JustifPhase
		bresps := make([]*ResponseBundle, 0, len(resps))
		for _, r := range resps {
			bresps = append(bresps, r)
		}
		if !p.sendJustifications(bresps) {
			return false
		}
		return true
	}
	finishFn := func() {
		if phase != JustifPhase {
			// although it should never happen twice but never too sure
			return
		}
		bjusts := make([]*JustificationBundle, 0, len(justifs))
		for _, j := range justifs {
			bjusts = append(bjusts, j)
		}
		p.finish(bjusts)
	}
	for {
		select {
		case newPhase := <-p.phaser.NextPhase():
			switch newPhase {
			case DealPhase:
				phase = DealPhase
				if !p.sendDeals() {
					return
				}
			case ResponsePhase:
				if !sendResponseFn() {
					return
				}
			case JustifPhase:
				if !sendJustifFn() {
					return
				}
			case FinishPhase:
				finishFn()
				return
			}
		case newDeal := <-p.board.IncomingDeal():
			if err := p.VerifySignature(newDeal); err == nil {
				// we make sure we don't see two deals from the same dealer that
				// are inconsistent - For example we might receive multiple
				// times the same deal from the network due to the use of
				// gossiping; here we make sure they're all consistent.
				if prevDeal, ok := deals[newDeal.Bundle.DealerIndex]; ok {
					prevHash := prevDeal.Hash()
					newHash := newDeal.Bundle.Hash()
					if !bytes.Equal(prevHash, newHash) {
						fmt.Printf("\n\n AIE AIE AIE\n\n")
						delete(deals, newDeal.Bundle.DealerIndex)
						continue
					}
				}
				deals[newDeal.Bundle.DealerIndex] = newDeal.Bundle
				var idxs []string
				for idx := range deals {
					idxs = append(idxs, strconv.Itoa(int(idx)))
				}
				fmt.Printf("-- %p nidx %d: new deal from %d received %d/%d : idx [%s]\n", p, p.dkg.nidx, newDeal.Bundle.DealerIndex, len(deals), oldN, strings.Join(idxs, ","))

			}
			// XXX This assumes we receive our own deal bundle since we use a
			// broadcast channel - may need to revisit that assumption
			if len(deals) == oldN {
				if !sendResponseFn() {
					return
				}
			}
		case newResp := <-p.board.IncomingResponse():
			// TODO See how can we deal with inconsistent answers from different
			// share holders
			if err := p.VerifySignature(newResp); err == nil {
				resps[newResp.Bundle.ShareIndex] = newResp.Bundle
			}
			if len(resps) == newN {
				if !sendJustifFn() {
					return
				}
			}
		case newJust := <-p.board.IncomingJustification():
			// TODO see how can we deal with inconsistent answers from different
			// dealers
			if err := p.VerifySignature(newJust); err == nil {
				justifs[newJust.Bundle.DealerIndex] = newJust.Bundle
			}
			if len(justifs) == oldN {
				finishFn()
				return
			}
		}
	}
}

// VerifySignature takes the index of the sender of the packet, computes the
// hash and verify if the signature is correct. VerifySignature expects a
// pointer to  an AuthDealBundle, AuthResponseBundle, or AuthJustifBundle.
// It returns nil if the Auth scheme in the config is nil.
func (p *Protocol) VerifySignature(packet interface{}) error {
	if p.conf.Auth == nil {
		return nil
	}
	var ok bool
	var hash []byte
	var pub kyber.Point
	var sig []byte
	switch auth := packet.(type) {
	case AuthDealBundle:
		hash = auth.Bundle.Hash()
		pub, ok = findIndex(p.conf.DkgConfig.OldNodes, auth.Bundle.DealerIndex)
		if !ok {
			return errors.New("no nodes with this public key")
		}
		sig = auth.Signature
		//fmt.Printf(" -- VERIFY Deal: index %d - pub %s - hash %x - sig %x - error? %s\n", auth.Bundle.DealerIndex, pub, hash, sig, p.conf.Auth.Verify(pub, hash, sig))
	case AuthResponseBundle:
		hash = auth.Bundle.Hash()
		pub, ok = findIndex(p.conf.DkgConfig.NewNodes, auth.Bundle.ShareIndex)
		if !ok {
			return errors.New("no nodes with this public key")
		}
		sig = auth.Signature
	case AuthJustifBundle:
		hash = auth.Bundle.Hash()
		pub, ok = findIndex(p.conf.DkgConfig.OldNodes, auth.Bundle.DealerIndex)
		if !ok {
			return errors.New("no nodes with this public key")
		}
		sig = auth.Signature
	default:
		return errors.New("unknown packet type")
	}

	err := p.conf.Auth.Verify(pub, hash, sig)
	if err != nil {
		fmt.Printf("\nINVALID SIGNATURE\n\n")
	}
	return err
}

type hashable interface {
	Hash() []byte
}

func (p *Protocol) signIt(h hashable) ([]byte, error) {
	msg := h.Hash()
	priv := p.conf.Longterm
	return p.conf.Auth.Sign(priv, msg)
}

func (p *Protocol) sendDeals() bool {
	if !p.canIssue {
		return true
	}
	bundle, err := p.dkg.Deals()
	if err != nil {
		p.res <- OptionResult{
			Error: err,
		}
		return false
	}
	authBundle := AuthDealBundle{
		Bundle: bundle,
	}
	if p.conf.Auth != nil {
		sig, err := p.signIt(bundle)
		if err != nil {
			return false
		}
		authBundle.Signature = sig
	}
	p.board.PushDeals(authBundle)
	return true
}

func (p *Protocol) sendResponses(deals []*DealBundle) bool {
	resp, err := p.dkg.ProcessDeals(deals)
	if err != nil {
		p.res <- OptionResult{
			Error: err,
		}
		// we signal the end since we can't go on
		return false
	}
	if resp != nil {
		authBundle := AuthResponseBundle{
			Bundle: resp,
		}
		if p.conf.Auth != nil {
			sig, err := p.signIt(resp)
			if err != nil {
				return false
			}
			authBundle.Signature = sig
		}
		p.board.PushResponses(authBundle)
	}
	return true
}

func (p *Protocol) sendJustifications(resps []*ResponseBundle) bool {
	res, just, err := p.dkg.ProcessResponses(resps)
	if err != nil {
		p.res <- OptionResult{
			Error: err,
		}
		return false
	}
	if res != nil {
		// we finished
		p.res <- OptionResult{
			Result: res,
		}
		return false
	}
	if just != nil {
		authBundle := AuthJustifBundle{
			Bundle: just,
		}
		if p.conf.Auth != nil {
			sig, err := p.signIt(just)
			if err != nil {
				return false
			}
			authBundle.Signature = sig
		}
		p.board.PushJustifications(authBundle)
	}
	return true
}

func (p *Protocol) finish(justifs []*JustificationBundle) {
	res, err := p.dkg.ProcessJustifications(justifs)
	p.res <- OptionResult{
		Error:  err,
		Result: res,
	}
}

func (p *Protocol) WaitEnd() <-chan OptionResult {
	return p.res
}

type OptionResult struct {
	Result *Result
	Error  error
}
