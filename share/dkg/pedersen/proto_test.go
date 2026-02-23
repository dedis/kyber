package dkg

import (
	"testing"
	"testing/synctest"
	"time"

	"github.com/stretchr/testify/require"

	"go.dedis.ch/kyber/v4"
	"go.dedis.ch/kyber/v4/group/edwards25519"
	"go.dedis.ch/kyber/v4/sign/schnorr"
	"go.dedis.ch/kyber/v4/util/random"
)

type TestNetwork struct {
	boards []*TestBoard
	noops  []uint32
}

func NewTestNetwork(n uint32) *TestNetwork {
	t := &TestNetwork{}
	for i := uint32(0); i < n; i++ {
		t.boards = append(t.boards, NewTestBoard(i, n, t))
	}
	return t
}

func (n *TestNetwork) SetNoop(index uint32) {
	n.noops = append(n.noops, index)
}

func (n *TestNetwork) BoardFor(index uint32) *TestBoard {
	for _, b := range n.boards {
		if b.index == index {
			return b
		}
	}
	panic("no such indexes")
}

func (n *TestNetwork) isNoop(i uint32) bool {
	for _, j := range n.noops {
		if i == j {
			return true
		}
	}
	return false
}

func (n *TestNetwork) BroadcastDeal(a *DealBundle) {
	for _, board := range n.boards {
		if !n.isNoop(board.index) {
			board.newDeals <- (*a)
		}
	}
}

func (n *TestNetwork) BroadcastResponse(a *ResponseBundle) {
	for _, board := range n.boards {
		if !n.isNoop(board.index) {
			board.newResps <- *a
		}
	}
}

func (n *TestNetwork) BroadcastJustification(a *JustificationBundle) {
	for _, board := range n.boards {
		if !n.isNoop(board.index) {
			board.newJusts <- *a
		}
	}
}

type TestBoard struct {
	index    uint32
	newDeals chan DealBundle
	newResps chan ResponseBundle
	newJusts chan JustificationBundle
	network  *TestNetwork
	badDeal  bool
	badSig   bool
}

func NewTestBoard(index uint32, n uint32, network *TestNetwork) *TestBoard {
	return &TestBoard{
		network:  network,
		index:    index,
		newDeals: make(chan DealBundle, n),
		newResps: make(chan ResponseBundle, n),
		newJusts: make(chan JustificationBundle, n),
	}
}

func (t *TestBoard) PushDeals(d *DealBundle) {
	if t.badDeal {
		d.Deals[0].EncryptedShare = []byte("bad bad bad")
	}
	if t.badSig {
		d.Signature = []byte("bad signature my friend")
	}
	t.network.BroadcastDeal(d)
}

func (t *TestBoard) PushResponses(r *ResponseBundle) {
	t.network.BroadcastResponse(r)
}

func (t *TestBoard) PushJustifications(j *JustificationBundle) {
	t.network.BroadcastJustification(j)
}

func (t *TestBoard) IncomingDeal() <-chan DealBundle {
	return t.newDeals
}

func (t *TestBoard) IncomingResponse() <-chan ResponseBundle {
	return t.newResps
}

func (t *TestBoard) IncomingJustification() <-chan JustificationBundle {
	return t.newJusts
}

func SetupProto(tns []*TestNode, period time.Duration, network *TestNetwork) {
	for _, n := range tns {
		n.phaser = NewTimePhaserFunc(func(Phase) {
			time.Sleep(period)
		})
		n.board = network.BoardFor(n.Index)
		c2 := *n.dkg.c
		proto, err := NewProtocol(&c2, n.board, n.phaser, false)
		if err != nil {
			panic(err)
		}
		n.proto = proto
	}
}

func TestProtoFull(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
    n := uint32(5)
		thr := n
		period := 1 * time.Second
		suite := edwards25519.NewBlakeSHA256Ed25519()
		tns := GenerateTestNodes(suite, n)
		list := NodesFromTest(tns)
		network := NewTestNetwork(n)
		dkgConf := Config{
			Suite:     suite,
			NewNodes:  list,
			Threshold: thr,
			Auth:      schnorr.NewScheme(suite),
		}
		SetupNodes(tns, &dkgConf)
		SetupProto(tns, period, network)

		var resCh = make(chan OptionResult, 1)
		// start all nodes and wait until each end
		for _, node := range tns {
			go func(n *TestNode) { resCh <- <-n.proto.WaitEnd() }(node)
		}
		// start the phasers
		for _, node := range tns {
			go node.phaser.Start()
		}
		// move two periods:
		// nodes already sent their deals, so they need to receive them after one
		// period, then they send their responses. Second period to receive the
		// responses, and then they send the justifications, if any.
		// since there is no faults we expect to receive the result only after two
		// periods.
		for i := 0; i < 2; i++ {
			time.Sleep(period + 100*time.Millisecond)
			synctest.Wait()
		}

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
		// we let the phaser finish all phases
		for i := 0; i < 2; i++ {
			time.Sleep(period + 100*time.Millisecond)
			synctest.Wait()
		}
	})
}

func TestProtoResharing(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
    n := uint32(5)
    thr := uint32(4)
		period := 1 * time.Second
		suite := edwards25519.NewBlakeSHA256Ed25519()
		tns := GenerateTestNodes(suite, n)
		list := NodesFromTest(tns)
		network := NewTestNetwork(n)
		dkgConf := Config{
			Suite:     suite,
			NewNodes:  list,
			Threshold: thr,
			Auth:      schnorr.NewScheme(suite),
		}
		SetupNodes(tns, &dkgConf)
		SetupProto(tns, period, network)

		var resCh = make(chan OptionResult, 1)
		// start all nodes and wait until each end
		for _, node := range tns {
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
		time.Sleep(100 * time.Millisecond)
		synctest.Wait()
		// move two periods:
		// nodes already sent they deals, so they need to receive them after one
		// period, then they send their responses. Second period to receive the
		// responses, and then they send the justifications, if any.
		// since there is no faults we expect to receive the result only after two
		// periods.
		for i := 0; i < 2; i++ {
			time.Sleep(period + 100*time.Millisecond)
		}

		// expect all results
		var results []*Result
		for optRes := range resCh {
			require.NoError(t, optRes.Error)
			results = append(results, optRes.Result)
      if len(results) == int(n) {
				break
			}
		}
		testResults(t, suite, thr, n, results)
		// we let the phaser finish all phases
		for i := 0; i < 2; i++ {
			time.Sleep(period + 100*time.Millisecond)
			synctest.Wait()
		}

		t.Log("\n\n ----- RESHARING ----\n\n")
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
		newConf := &Config{
			Suite:        suite,
			NewNodes:     newList,
			OldNodes:     list,
			Threshold:    newT,
			OldThreshold: thr,
			Auth:         schnorr.NewScheme(suite),
		}

		SetupReshareNodes(newTns, newConf, tns[0].res.Key.Commits)
		SetupProto(newTns, period, network)

		resCh = make(chan OptionResult, 1)
		// start all nodes and wait until each end
		for _, node := range newTns {
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
		// move three periods:
		// nodes already sent they deals, so they need to receive them after one
		// period, then they send their responses. Second period to receive the
		// responses, and then they send the justifications, if any. A third period
		// is needed to receive all justifications.
		for i := 0; i < 3; i++ {
			time.Sleep(period + 100*time.Millisecond)
			synctest.Wait()
		}

		// expect all results
		results = nil
		for optRes := range resCh {
			require.NoError(t, optRes.Error)
			results = append(results, optRes.Result)
			t.Logf("GOT %d RESULTS\n", len(results))
      if len(results) == int(newN) {
				break
			}
		}
		testResults(t, suite, newT, newN, results)
		// we let the phaser finish all phases
		time.Sleep(period + 100*time.Millisecond)
		synctest.Wait()
	})
}

func TestProtoThreshold(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
    n := uint32(5)
    realN := uint32(4)
    thr := uint32(4)
		period := 1 * time.Second
		suite := edwards25519.NewBlakeSHA256Ed25519()
		tns := GenerateTestNodes(suite, n)
		list := NodesFromTest(tns)
		tns = tns[:realN]
		network := NewTestNetwork(realN)
		dkgConf := Config{
			Suite:     suite,
			NewNodes:  list,
			Threshold: thr,
			Auth:      schnorr.NewScheme(suite),
		}
		SetupNodes(tns, &dkgConf)
		SetupProto(tns, period, network)

		var resCh = make(chan OptionResult, 1)
		// start all nodes and wait until each end
		for _, node := range tns {
			go func(n *TestNode) { resCh <- <-n.proto.WaitEnd() }(node)
		}
		// start the phasers
		for _, node := range tns {
			go node.phaser.Start()
		}
		time.Sleep(100 * time.Millisecond)
		synctest.Wait()
		// move three periods:
		// nodes already sent they deals, so they need to receive them after one
		// period, then they send their responses. Second period to receive the
		// responses, and then they send the justifications, if any. A third period
		// is needed to receive all justifications.
		for i := 0; i < 3; i++ {
			time.Sleep(period + 100*time.Millisecond)
			synctest.Wait()
		}
		// expect all results
		var results []*Result
		for optRes := range resCh {
			require.NoError(t, optRes.Error)
			results = append(results, optRes.Result)
      if len(results) == int(realN) {
				break
			}
		}
		testResults(t, suite, thr, n, results)
		// we let the phaser finish its last period
		time.Sleep(period + 100*time.Millisecond)
		synctest.Wait()
	})
}

func TestProtoFullFast(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
    n := uint32(5)
    thr := uint32(n)
		period := 1 * time.Second
		suite := edwards25519.NewBlakeSHA256Ed25519()
		tns := GenerateTestNodes(suite, n)
		list := NodesFromTest(tns)
		network := NewTestNetwork(n)
		dkgConf := Config{
			FastSync:  true,
			Suite:     suite,
			NewNodes:  list,
			Threshold: thr,
			Auth:      schnorr.NewScheme(suite),
		}
		SetupNodes(tns, &dkgConf)
		SetupProto(tns, period, network)

		var resCh = make(chan OptionResult, 1)
		// start all nodes and wait until each end
		for _, node := range tns {
			go func(n *TestNode) { resCh <- <-n.proto.WaitEnd() }(node)
		}
		// start the phasers
		for _, node := range tns {
			// every node will start when phase starts
			go node.phaser.Start()
		}

		time.Sleep(period + 100*time.Millisecond)
		synctest.Wait()
		// expect all results
		var results []*Result
		for optRes := range resCh {
			require.NoError(t, optRes.Error)
			results = append(results, optRes.Result)
      if len(results) == int(n) {
				break
			}
		}
		testResults(t, suite, thr, n, results)
		// we let the phaser finish
		time.Sleep(3*period + 100*time.Millisecond)
		synctest.Wait()
	})
}

func TestProtoResharingAbsent(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
    n := uint32(4)
    thr := uint32(3)
		// we setup now the second group with one node left from old group and two
		// new node
		newN := n + 1
		newT := thr + 1

		period := 1 * time.Second
		suite := edwards25519.NewBlakeSHA256Ed25519()
		tns := GenerateTestNodes(suite, n)
		list := NodesFromTest(tns)
		network := NewTestNetwork(n)
		dkgConf := Config{
			Suite:     suite,
			NewNodes:  list,
			Threshold: thr,
			Auth:      schnorr.NewScheme(suite),
		}
		SetupNodes(tns, &dkgConf)
		SetupProto(tns, period, network)

		var resCh = make(chan OptionResult, 1)
		// start all nodes and wait until each end
		for _, node := range tns {
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
		time.Sleep(100 * time.Millisecond)
		synctest.Wait()
		// move two periods:
		// nodes already sent they deals, so they need to receive them after one
		// period, then they send their responses. Second period to receive the
		// responses, and then they send the justifications, if any.
		// since there is no faults we expect to receive the result only after two
		// periods.
		for i := 0; i < 2; i++ {
			time.Sleep(period + 100*time.Millisecond)
			synctest.Wait()
		}

		// expect all results
		var results []*Result
		for optRes := range resCh {
			require.NoError(t, optRes.Error)
			results = append(results, optRes.Result)
      if len(results) == int(n) {
				break
			}
		}
		testResults(t, suite, thr, n, results)

		t.Logf("\n\n ----- RESHARING ----\n\n")
		// RESHARING
		var newTns = make([]*TestNode, newN)
		copy(newTns, tns[:n-1])
		//  new node can have the same index as a previous one, separation is made
		newTns[n-1] = NewTestNode(suite, n-1)
		newTns[n] = NewTestNode(suite, n)
		network = NewTestNetwork(newN)
		newList := NodesFromTest(newTns)
		newConf := &Config{
			Suite:        suite,
			NewNodes:     newList,
			OldNodes:     list,
			Threshold:    newT,
			OldThreshold: thr,
			Auth:         schnorr.NewScheme(suite),
		}

		SetupReshareNodes(newTns, newConf, tns[0].res.Key.Commits)
		SetupProto(newTns, period, network)
		///
		/// We set a node as registered but offline
		///
		network.SetNoop(newTns[0].Index)
		resCh = make(chan OptionResult, 1)
		// start all nodes and wait until each end
		for _, node := range newTns {
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
		time.Sleep(100 * time.Millisecond)
		// move three periods:
		// nodes already sent they deals, so they need to receive them after one
		// period, then they send their responses. Second period to receive the
		// responses, and then they send the justifications, if any. A third period
		// is needed to receive all justifications.
		for i := 0; i < 3; i++ {
			time.Sleep(period + 100*time.Millisecond)
			synctest.Wait()
		}

		// expect results-1 OK and 1 Err
		results = nil
		var errNode error
		for optRes := range resCh {
			if optRes.Error != nil {
				t.Logf("GOT ONE ERROR\n")
				require.Nil(t, errNode, "already an error saved!?")
				errNode = optRes.Error
				continue
			}
			results = append(results, optRes.Result)
			t.Logf("GOT %d RESULTS\n", len(results))
      if len(results) == int(newN-1) {
				break
			}
		}
		testResults(t, suite, newT, newN, results)
	})
}

func TestProtoThresholdFast(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
    n := uint32(5)
    thr := uint32(4)
		period := 1 * time.Second
		suite := edwards25519.NewBlakeSHA256Ed25519()
		tns := GenerateTestNodes(suite, n)
		list := NodesFromTest(tns)
		network := NewTestNetwork(n)
		dkgConf := Config{
			FastSync:  true,
			Suite:     suite,
			NewNodes:  list,
			Threshold: thr,
			Auth:      schnorr.NewScheme(suite),
		}
		SetupNodes(tns, &dkgConf)
		SetupProto(tns, period, network)
		// set a node that will send a bad deal such that all deals are received
		// "fast", then the normal rounds are happening
		network.BoardFor(1).badDeal = true

		var resCh = make(chan OptionResult, 1)
		// start all nodes and wait until each end
		for _, node := range tns {
			if node.Index != 1 {
				go func(n *TestNode) { resCh <- <-n.proto.WaitEnd() }(node)
			}
		}
		// start the phasers
		for _, node := range tns {
			go node.phaser.Start()
		}
		time.Sleep(100 * time.Millisecond)
		synctest.Wait()
		// move three periods:
		// nodes already sent they deals, so they need to receive them after one
		// period, then they send their responses. Second period to receive the
		// responses, and then they send the justifications, if any. A third period
		// is needed to receive all justifications.
		// NOTE the first period is ignored by the protocol but timer still sends
		// it.
		for i := 0; i < 3; i++ {
			time.Sleep(period + 100*time.Millisecond)
			synctest.Wait()
		}
		// expect all results consistent except for the node 1
		var results []*Result
		for optRes := range resCh {
			require.NoError(t, optRes.Error)
			results = append(results, optRes.Result)
      if len(results) == int(n-1) {
				break
			}
		}
		testResults(t, suite, thr, n, results)
		// test that they exclude the bad node
		for _, res := range results {
			for _, node := range res.QUAL {
				require.NotEqual(t, uint32(1), node.Index)
			}
		}
	})
}

func generateDeal(idx Index) *DealBundle {
	suite := edwards25519.NewBlakeSHA256Ed25519()
	deals := make([]Deal, 2)
	deals[0].ShareIndex = 56
	deals[1].ShareIndex = 57
	deals[0].EncryptedShare = []byte("My first secure share")
	deals[1].EncryptedShare = []byte("It keeps getting more secure")
	return &DealBundle{
		DealerIndex: idx,
		Deals:       deals,
		Public:      []kyber.Point{suite.Point().Pick(random.New())},
		SessionID:   []byte("Blob"),
	}
}

func TestSet(t *testing.T) {
	s := newSet()
	deal := generateDeal(1)
	s.Push(deal)
	require.NotNil(t, s.vals[1])
	require.Nil(t, s.bad)
	// push a second time shouldn't change the set
	s.Push(deal)
	require.NotNil(t, s.vals[1])
	require.Nil(t, s.bad)

	deal2 := generateDeal(2)
	s.Push(deal2)
	require.Equal(t, 2, len(s.vals))
	require.Nil(t, s.bad)

	// push a different deal
	deal1b := generateDeal(1)
	s.Push(deal1b)
	require.Equal(t, 1, len(s.vals))
	require.Contains(t, s.bad, Index(1))

	// try again, it should fail directly
	s.Push(deal1b)
	require.Equal(t, 1, len(s.vals))
	require.Contains(t, s.bad, Index(1))

}

func TestProtoSkip(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
    n := uint32(5)
    thr := uint32(4)
    period := 1 * time.Second
    suite := edwards25519.NewBlakeSHA256Ed25519()
    tns := GenerateTestNodes(suite, n)
    list := NodesFromTest(tns)
    network := NewTestNetwork(n)
    dkgConf := Config{
      FastSync:  false,
      Suite:     suite,
      NewNodes:  list,
      Threshold: thr,
      Auth:      schnorr.NewScheme(suite),
    }
    SetupNodes(tns, &dkgConf)
    SetupProto(tns, period, network)
    for _, tn := range tns {
      tn.proto.skipVerif = true
    }

		network.BoardFor(1).badSig = true

		var resCh = make(chan OptionResult, 1)
		// start all nodes and wait until each end
		for _, node := range tns {
			go func(n *TestNode) { resCh <- <-n.proto.WaitEnd() }(node)
		}
		// start the phasers
		for _, node := range tns {
			go node.phaser.Start()
		}
		// we go through 2 periods
		for i := 0; i < 2; i++ {
			time.Sleep(period + 100*time.Millisecond)
			synctest.Wait()
		}
		// expect all results
		var results []*Result
		for optRes := range resCh {
			//require.NoError(t, optRes.Error)
			results = append(results, optRes.Result)
			if len(results) == n {
				break
			}
		}
		// check that all dkgs have all good entries
		// that should be the case since signature verification is not performed
		for _, tn := range tns {
			require.True(t, tn.proto.dkg.statuses.CompleteSuccess(), "%d: %p-> %s", tn.Index, tn.proto.dkg, tn.proto.dkg.statuses.String())
		}
		// we let the phaser finish
		time.Sleep(2 * period)
		synctest.Wait()
	})
}
