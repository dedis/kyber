package dkg

import (
	"fmt"
	"testing"
	"time"

	"github.com/drand/kyber/group/edwards25519"
	"github.com/drand/kyber/sign/schnorr"
	clock "github.com/jonboulle/clockwork"
	"github.com/stretchr/testify/require"
)

type TestNetwork struct {
	boards []*TestBoard
}

func NewTestNetwork(n int) *TestNetwork {
	t := &TestNetwork{}
	for i := 0; i < n; i++ {
		t.boards = append(t.boards, NewTestBoard(uint32(i), n, t))
	}
	return t
}

func (n *TestNetwork) BoardFor(index uint32) *TestBoard {
	for _, b := range n.boards {
		if b.index == index {
			return b
		}
	}
	panic("no such indexes")
}

func (n *TestNetwork) BroadcastDeal(a AuthDealBundle) {
	for _, board := range n.boards {
		board.newDeals <- a
	}
}

func (n *TestNetwork) BroadcastResponse(a AuthResponseBundle) {
	for _, board := range n.boards {
		board.newResps <- a
	}
}

func (n *TestNetwork) BroadcastJustification(a AuthJustifBundle) {
	for _, board := range n.boards {
		board.newJusts <- a
	}
}

type TestBoard struct {
	index    uint32
	newDeals chan AuthDealBundle
	newResps chan AuthResponseBundle
	newJusts chan AuthJustifBundle
	network  *TestNetwork
}

func NewTestBoard(index uint32, n int, network *TestNetwork) *TestBoard {
	return &TestBoard{
		network:  network,
		index:    index,
		newDeals: make(chan AuthDealBundle, n),
		newResps: make(chan AuthResponseBundle, n),
		newJusts: make(chan AuthJustifBundle, n),
	}
}

func (t *TestBoard) PushDeals(d AuthDealBundle) {
	t.network.BroadcastDeal(d)
}

func (t *TestBoard) PushResponses(r AuthResponseBundle) {
	t.network.BroadcastResponse(r)
}

func (t *TestBoard) PushJustification(j AuthJustifBundle) {
	t.network.BroadcastJustification(j)
}

func (t *TestBoard) IncomingDeal() <-chan AuthDealBundle {
	return t.newDeals
}

func (t *TestBoard) IncomingResponse() <-chan AuthResponseBundle {
	return t.newResps
}

func (t *TestBoard) IncomingJustification() <-chan AuthJustifBundle {
	return t.newJusts
}

func SetupProto(tns []*TestNode, dkgC *DkgConfig, protoC *Config, period time.Duration, network *TestNetwork) {
	for _, n := range tns {
		clock := clock.NewFakeClock()
		n.clock = clock
		n.phaser = NewTimePhaserFunc(func() {
			clock.Sleep(period)
			fmt.Printf(" - finished sleeping\n")
		})
		n.board = network.BoardFor(n.Index)
		c2 := *protoC
		c2.DkgConfig = n.dkg.c
		proto, err := NewProtocol(&c2, n.board, n.phaser)
		if err != nil {
			panic(err)
		}
		n.proto = proto
	}
}

func moveTime(tns []*TestNode, p time.Duration) {
	for _, node := range tns {
		node.clock.Advance(p)
	}
}

func TestProtoFull(t *testing.T) {
	n := 5
	thr := n
	period := 1 * time.Second
	suite := edwards25519.NewBlakeSHA256Ed25519()
	tns := GenerateTestNodes(suite, n)
	list := NodesFromTest(tns)
	network := NewTestNetwork(n)
	dkgConf := DkgConfig{
		Suite:     suite,
		NewNodes:  list,
		Threshold: thr,
	}
	protoConf := Config{
		Auth: schnorr.NewScheme(suite),
	}
	SetupNodes(tns, &dkgConf)
	SetupProto(tns, &dkgConf, &protoConf, period, network)

	var resCh = make(chan OptionResult, 1)
	// start all nodes and wait until each end
	for _, node := range tns {
		go node.proto.Start()
		go func(n *TestNode) { resCh <- <-n.proto.WaitEnd() }(node)
	}
	// start the phasers
	for _, node := range tns {
		go node.phaser.Start()
	}
	// move three periods: start where node send deals, then nodes receive deal
	// and send responses, then nodes processes response
	// since there is no faults we expect to receive all results
	moveTime(tns, period)
	time.Sleep(100 * time.Millisecond)
	moveTime(tns, period)
	time.Sleep(100 * time.Millisecond)
	moveTime(tns, period)

	// expect all results
	var results []*Result
	for optRes := range resCh {
		require.NoError(t, optRes.Error)
		results = append(results, optRes.Result)
		if len(results) == n {
			break
		}
	}
	testResults(t, suite, thr, n, results)

}

func TestProtoResharing(t *testing.T) {
	n := 5
	thr := 4
	period := 1 * time.Second
	suite := edwards25519.NewBlakeSHA256Ed25519()
	tns := GenerateTestNodes(suite, n)
	list := NodesFromTest(tns)
	network := NewTestNetwork(n)
	dkgConf := DkgConfig{
		Suite:     suite,
		NewNodes:  list,
		Threshold: thr,
	}
	protoConf := Config{
		Auth: schnorr.NewScheme(suite),
	}
	SetupNodes(tns, &dkgConf)
	SetupProto(tns, &dkgConf, &protoConf, period, network)

	var resCh = make(chan OptionResult, 1)
	// start all nodes and wait until each end
	for _, node := range tns {
		go node.proto.Start()
		go func(n *TestNode) {
			optRes := <-n.proto.WaitEnd()
			n.res = optRes.Result
			resCh <- optRes
		}(node)

	}
	// start the phasers
	for _, node := range tns {
		go node.phaser.Start()
	}
	// move three periods: start where node send deals, then nodes receive deal
	// and send responses, then nodes processes response
	// since there is no faults we expect to receive all results
	moveTime(tns, period)
	time.Sleep(100 * time.Millisecond)
	moveTime(tns, period)
	time.Sleep(100 * time.Millisecond)
	moveTime(tns, period)

	// expect all results
	var results []*Result
	for optRes := range resCh {
		require.NoError(t, optRes.Error)
		results = append(results, optRes.Result)
		if len(results) == n {
			break
		}
	}
	testResults(t, suite, thr, n, results)

	fmt.Printf("\n\n ----- RESHARING ----\n\n")
	// RESHARING
	// we setup now the second group with one node left from old group and two
	// new node
	newN := n + 1
	newT := thr + 1
	var newTns = make([]*TestNode, newN)
	copy(newTns, tns[:n-1])
	//  new node can have the same index as a previous one, separation is made
	newTns[n-1] = NewTestNode(suite, n-1)
	newTns[n] = NewTestNode(suite, n)
	network = NewTestNetwork(newN)
	newList := NodesFromTest(newTns)
	newConf := &DkgConfig{
		Suite:        suite,
		NewNodes:     newList,
		OldNodes:     list,
		Threshold:    newT,
		OldThreshold: thr,
	}
	newProtoConf := Config{
		Auth: schnorr.NewScheme(suite),
	}

	SetupReshareNodes(newTns, newConf, tns[0].res.Key.Commits)
	SetupProto(newTns, newConf, &newProtoConf, period, network)

	resCh = make(chan OptionResult, 1)
	// start all nodes and wait until each end
	for _, node := range newTns {
		go node.proto.Start()
		go func(n *TestNode) {
			optRes := <-n.proto.WaitEnd()
			n.res = optRes.Result
			resCh <- optRes
		}(node)
	}
	// start the phasers
	for _, node := range newTns {
		go node.phaser.Start()
	}
	// move three periods: start where node send deals, then nodes receive deal
	// and send responses, then nodes processes response and send justifs.then
	// last period to wait for justifs and return result
	moveTime(newTns, period)
	time.Sleep(100 * time.Millisecond)
	moveTime(newTns, period)
	time.Sleep(100 * time.Millisecond)
	moveTime(newTns, period)
	time.Sleep(100 * time.Millisecond)
	moveTime(newTns, period)

	// expect all results
	results = nil
	for optRes := range resCh {
		require.NoError(t, optRes.Error)
		results = append(results, optRes.Result)
		fmt.Printf("GOT %d RESULTS\n", len(results))
		if len(results) == newN {
			break
		}
	}
	testResults(t, suite, newT, newN, results)
}

func TestProtoThreshold(t *testing.T) {
	n := 5
	realN := 4
	thr := 4
	period := 1 * time.Second
	suite := edwards25519.NewBlakeSHA256Ed25519()
	tns := GenerateTestNodes(suite, n)
	list := NodesFromTest(tns)
	tns = tns[:realN]
	network := NewTestNetwork(realN)
	dkgConf := DkgConfig{
		Suite:     suite,
		NewNodes:  list,
		Threshold: thr,
	}
	protoConf := Config{
		Auth: schnorr.NewScheme(suite),
	}
	SetupNodes(tns, &dkgConf)
	SetupProto(tns, &dkgConf, &protoConf, period, network)

	var resCh = make(chan OptionResult, 1)
	// start all nodes and wait until each end
	for _, node := range tns {
		go node.proto.Start()
		go func(n *TestNode) { resCh <- <-n.proto.WaitEnd() }(node)
	}
	// start the phasers
	for _, node := range tns {
		go node.phaser.Start()
	}
	// move three periods: start where node send deals, then nodes receive deal
	// and send responses, then nodes processes response
	// since there is no faults we expect to receive all results
	moveTime(tns, period)
	time.Sleep(100 * time.Millisecond)
	moveTime(tns, period)
	time.Sleep(100 * time.Millisecond)
	moveTime(tns, period)
	time.Sleep(100 * time.Millisecond)
	moveTime(tns, period)
	time.Sleep(100 * time.Millisecond)
	moveTime(tns, period)

	// expect all results
	var results []*Result
	for optRes := range resCh {
		require.NoError(t, optRes.Error)
		results = append(results, optRes.Result)
		if len(results) == realN {
			break
		}
	}
	testResults(t, suite, thr, n, results)

}
