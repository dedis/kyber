package dkg

import (
	"bytes"
	"fmt"
	"strings"
	"time"
)

// Board is the interface between the dkg protocol and the external world. It
// consists in pushing packets out to other nodes and receiving in packets from
// the other nodes. A common board would use the network as the underlying
// communication mechanism but one can also use a smart contract based
// approach.
type Board interface {
	PushDeals(*DealBundle)
	IncomingDeal() <-chan DealBundle
	PushResponses(*ResponseBundle)
	IncomingResponse() <-chan ResponseBundle
	PushJustifications(*JustificationBundle)
	IncomingJustification() <-chan JustificationBundle
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
	board     Board
	phaser    Phaser
	dkg       *DistKeyGenerator
	canIssue  bool
	res       chan OptionResult
	skipVerif bool
}

// XXX TO DELETE
func printNodes(list []Node) string {
	var arr []string
	for _, node := range list {
		arr = append(arr, fmt.Sprintf("[%d : %s]", node.Index, node.Public))
	}
	return strings.Join(arr, "\n")
}

func NewProtocol(c *Config, b Board, phaser Phaser, skipVerification bool) (*Protocol, error) {
	dkg, err := NewDistKeyHandler(c)
	if err != nil {
		return nil, err
	}
	p := &Protocol{
		board:     b,
		phaser:    phaser,
		dkg:       dkg,
		canIssue:  dkg.canIssue,
		res:       make(chan OptionResult, 1),
		skipVerif: skipVerification,
	}
	go p.Start()
	return p, nil
}

func (p *Protocol) Start() {
	var fastSync = p.dkg.c.FastSync
	if fastSync {
		p.startFast()
		return
	}
	var deals = newSet()
	var resps = newSet()
	var justifs = newSet()
	for {
		select {
		case newPhase := <-p.phaser.NextPhase():
			switch newPhase {
			case DealPhase:
				if !p.sendDeals() {
					return
				}
			case ResponsePhase:
				if !p.sendResponses(deals.ToDeals()) {
					return
				}
			case JustifPhase:
				if !p.sendJustifications(resps.ToResponses()) {
					return
				}
			case FinishPhase:
				p.finish(justifs.ToJustifications())
				return
			}
		case newDeal := <-p.board.IncomingDeal():
			if err := p.verify(&newDeal); err == nil {
				deals.Push(&newDeal)
			}
		case newResp := <-p.board.IncomingResponse():
			if err := p.verify(&newResp); err == nil {
				resps.Push(&newResp)
			}
		case newJust := <-p.board.IncomingJustification():
			if err := p.verify(&newJust); err == nil {
				justifs.Push(&newJust)
			}
		}
	}
}

func (p *Protocol) startFast() {
	var deals = newSet()
	var resps = newSet()
	var justifs = newSet()
	var newN = len(p.dkg.c.NewNodes)
	var oldN = len(p.dkg.c.OldNodes)
	var phase Phase
	sendResponseFn := func() bool {
		if phase != DealPhase {
			return true
		}
		phase = ResponsePhase
		if !p.sendResponses(deals.ToDeals()) {
			return false
		}
		return true
	}
	sendJustifFn := func() bool {
		if phase != ResponsePhase {
			return true
		}
		phase = JustifPhase
		if !p.sendJustifications(resps.ToResponses()) {
			return false
		}
		return true
	}
	finishFn := func() {
		if phase != JustifPhase {
			// although it should never happen twice but never too sure
			return
		}
		p.finish(justifs.ToJustifications())
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
			if err := p.verify(&newDeal); err == nil {
				deals.Push(&newDeal)
			}
			if deals.Len() == oldN {
				if !sendResponseFn() {
					return
				}
			}
		case newResp := <-p.board.IncomingResponse():
			if err := p.verify(&newResp); err == nil {
				resps.Push(&newResp)
			}
			if resps.Len() == newN {
				if !sendJustifFn() {
					return
				}
			}
		case newJust := <-p.board.IncomingJustification():
			if err := p.verify(&newJust); err == nil {
				justifs.Push(&newJust)
			}
			if justifs.Len() == oldN {
				finishFn()
				return
			}
		}
	}
}

func (p *Protocol) verify(packet Packet) error {
	if p.skipVerif {
		return nil
	}

	return VerifyPacketSignature(p.dkg.c, packet)
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
	if bundle != nil {
		p.board.PushDeals(bundle)
	}
	return true
}

func (p *Protocol) sendResponses(deals []*DealBundle) bool {
	bundle, err := p.dkg.ProcessDeals(deals)
	if err != nil {
		p.res <- OptionResult{
			Error: err,
		}
		// we signal the end since we can't go on
		return false
	}
	if bundle != nil {
		p.board.PushResponses(bundle)
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
		p.board.PushJustifications(just)
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

type set struct {
	vals map[Index]Packet
	bad  []Index
}

func newSet() *set {
	return &set{
		vals: make(map[Index]Packet),
	}
}

func (s *set) Push(p Packet) {
	hash := p.Hash()
	idx := p.Index()
	if s.isBad(idx) {
		// already misbehaved before
		return
	}
	prev, present := s.vals[idx]
	if present {
		if !bytes.Equal(prev.Hash(), hash) {
			// bad behavior - we evict
			delete(s.vals, idx)
			s.bad = append(s.bad, idx)
		}
		// same packet just rebroadcasted - all good
		return
	}
	s.vals[idx] = p
}

func (s *set) isBad(idx Index) bool {
	for _, i := range s.bad {
		if idx == i {
			return true
		}
	}
	return false
}

func (s *set) ToDeals() []*DealBundle {
	deals := make([]*DealBundle, 0, len(s.vals))
	for _, p := range s.vals {
		deals = append(deals, p.(*DealBundle))
	}
	return deals
}

func (s *set) ToResponses() []*ResponseBundle {
	resps := make([]*ResponseBundle, 0, len(s.vals))
	for _, p := range s.vals {
		resps = append(resps, p.(*ResponseBundle))
	}
	return resps
}

func (s *set) ToJustifications() []*JustificationBundle {
	justs := make([]*JustificationBundle, 0, len(s.vals))
	for _, p := range s.vals {
		justs = append(justs, p.(*JustificationBundle))
	}
	return justs
}

func (s *set) Len() int {
	return len(s.vals)
}
