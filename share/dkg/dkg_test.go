package dkg

import (
	"errors"
	"fmt"
	"math/rand"
	"testing"

	clock "github.com/jonboulle/clockwork"
	"github.com/stretchr/testify/require"
	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/kyber/v3/group/edwards25519"
	"go.dedis.ch/kyber/v3/pairing/bn256"
	"go.dedis.ch/kyber/v3/share"
	"go.dedis.ch/kyber/v3/sign/schnorr"
	"go.dedis.ch/kyber/v3/sign/tbls"
	"go.dedis.ch/kyber/v3/util/random"
)

type TestNode struct {
	Index   uint32
	Private kyber.Scalar
	Public  kyber.Point
	dkg     *DistKeyGenerator
	res     *Result
	proto   *Protocol
	phaser  *TimePhaser
	board   *TestBoard
	clock   clock.FakeClock
}

func NewTestNode(s Suite, index int) *TestNode {
	private := s.Scalar().Pick(random.New())
	public := s.Point().Mul(private, nil)
	return &TestNode{
		Index:   uint32(index),
		Private: private,
		Public:  public,
	}
}

func GenerateTestNodes(s Suite, n int) []*TestNode {
	tns := make([]*TestNode, n)
	for i := 0; i < n; i++ {
		tns[i] = NewTestNode(s, i)
	}
	return tns
}

func NodesFromTest(tns []*TestNode) []Node {
	nodes := make([]Node, len(tns))
	for i := 0; i < len(tns); i++ {
		nodes[i] = Node{
			Index:  tns[i].Index,
			Public: tns[i].Public,
		}
	}
	return nodes
}

// inits the dkg structure
func SetupNodes(nodes []*TestNode, c *Config) {
	nonce := GetNonce()
	for _, n := range nodes {
		c2 := *c
		c2.Longterm = n.Private
		c2.Nonce = nonce
		dkg, err := NewDistKeyHandler(&c2)
		if err != nil {
			panic(err)
		}
		n.dkg = dkg
	}
}

func SetupReshareNodes(nodes []*TestNode, c *Config, coeffs []kyber.Point) {
	nonce := GetNonce()
	for _, n := range nodes {
		c2 := *c
		c2.Longterm = n.Private
		c2.Nonce = nonce
		if n.res != nil {
			c2.Share = n.res.Key
		} else {
			c2.PublicCoeffs = coeffs
		}
		dkg, err := NewDistKeyHandler(&c2)
		if err != nil {
			panic(err)
		}
		n.dkg = dkg
	}
}

func IsDealerIncluded(bundles []*ResponseBundle, dealer uint32) bool {
	for _, bundle := range bundles {
		for _, resp := range bundle.Responses {
			if resp.DealerIndex == dealer {
				return true
			}
		}
	}
	return false
}

func testResults(t *testing.T, suite Suite, thr, n int, results []*Result) {
	// test if all results are consistent
	for i, res := range results {
		require.Equal(t, thr, len(res.Key.Commitments()))
		for j, res2 := range results {
			if i == j {
				continue
			}
			require.True(t, res.PublicEqual(res2), "res %+v != %+v", res, res2)
		}
	}
	// test if re-creating secret key gives same public key
	var shares []*share.PriShare
	for _, res := range results {
		shares = append(shares, res.Key.PriShare())
	}
	// test if shares are public polynomial evaluation
	exp := share.NewPubPoly(suite, suite.Point().Base(), results[0].Key.Commitments())
	for _, share := range shares {
		pubShare := exp.Eval(share.I)
		expShare := suite.Point().Mul(share.V, nil)
		require.True(t, pubShare.V.Equal(expShare), "share %s give pub %s vs exp %s", share.V.String(), pubShare.V.String(), expShare.String())
	}

	secretPoly, err := share.RecoverPriPoly(suite, shares, thr, n)
	require.NoError(t, err)
	gotPub := secretPoly.Commit(suite.Point().Base())
	require.True(t, exp.Equal(gotPub))

	secret, err := share.RecoverSecret(suite, shares, thr, n)
	require.NoError(t, err)
	public := suite.Point().Mul(secret, nil)
	expKey := results[0].Key.Public()
	require.True(t, public.Equal(expKey))

}

type MapDeal func([]*DealBundle) []*DealBundle
type MapResponse func([]*ResponseBundle) []*ResponseBundle
type MapJustif func([]*JustificationBundle) []*JustificationBundle

func RunDKG(t *testing.T, tns []*TestNode, conf Config,
	dm MapDeal, rm MapResponse, jm MapJustif) []*Result {

	SetupNodes(tns, &conf)
	var deals []*DealBundle
	for _, node := range tns {
		d, err := node.dkg.Deals()
		require.NoError(t, err)
		deals = append(deals, d)
	}

	if dm != nil {
		deals = dm(deals)
	}

	var respBundles []*ResponseBundle
	for _, node := range tns {
		resp, err := node.dkg.ProcessDeals(deals)
		require.NoError(t, err)
		if resp != nil {
			respBundles = append(respBundles, resp)
		}
	}

	if rm != nil {
		respBundles = rm(respBundles)
	}

	var justifs []*JustificationBundle
	var results []*Result
	for _, node := range tns {
		res, just, err := node.dkg.ProcessResponses(respBundles)
		if !errors.Is(err, ErrEvicted) {
			// there should not be any other error than eviction
			require.NoError(t, err)
		}
		if res != nil {
			results = append(results, res)
		} else if just != nil {
			justifs = append(justifs, just)
		}
	}

	if len(justifs) == 0 {
		return results
	}

	if jm != nil {
		justifs = jm(justifs)
	}

	for _, node := range tns {
		res, err := node.dkg.ProcessJustifications(justifs)
		if errors.Is(err, ErrEvicted) {
			continue
		}
		require.NoError(t, err)
		require.NotNil(t, res)
		results = append(results, res)
	}
	return results
}

// This tests makes a dealer being evicted and checks if the dealer knows about the eviction
// itself and quits the DKG
func TestSelfEvictionDealer(t *testing.T) {
	n := 5
	thr := 3
	suite := edwards25519.NewBlakeSHA256Ed25519()
	tns := GenerateTestNodes(suite, n)
	skippedIndex := rand.Intn(n)
	var newIndex uint32 = 53 // XXX should there be a limit to the index ?
	tns[skippedIndex].Index = newIndex
	list := NodesFromTest(tns)
	conf := Config{
		Suite:     suite,
		NewNodes:  list,
		Threshold: thr,
		Auth:      schnorr.NewScheme(suite),
		FastSync:  true,
	}
	SetupNodes(tns, &conf)

	dealerToEvict := list[0].Index
	var deals []*DealBundle
	for _, node := range tns {
		d, err := node.dkg.Deals()
		require.NoError(t, err)
		if node.Index == dealerToEvict {
			// we simulate that this node doesn't send its deal
			continue
		}
		deals = append(deals, d)
	}

	var respBundles []*ResponseBundle
	for _, node := range tns {
		resp, err := node.dkg.ProcessDeals(deals)
		require.NoError(t, err)
		if resp != nil {
			respBundles = append(respBundles, resp)
		}
	}

	for _, node := range tns {
		_, _, err := node.dkg.ProcessResponses(respBundles)
		if node.Index == dealerToEvict {
			// we are evicting ourselves here so we should stop doing the DKG
			require.Error(t, err)
			continue
		}
		require.NoError(t, err)
		require.True(t, contains(node.dkg.evicted, dealerToEvict))
	}
}

// This test is running DKG and resharing with skipped indices given there is no
// guarantees that the indices of the nodes are going to be sequentials.
func TestDKGSkipIndex(t *testing.T) {
	n := 5
	thr := 4
	suite := edwards25519.NewBlakeSHA256Ed25519()
	tns := GenerateTestNodes(suite, n)
	skippedIndex := 1
	var newIndex uint32 = 53 // XXX should there be a limit to the index ?
	tns[skippedIndex].Index = newIndex
	list := NodesFromTest(tns)
	conf := Config{
		Suite:     suite,
		NewNodes:  list,
		Threshold: thr,
		Auth:      schnorr.NewScheme(suite),
	}
	results := RunDKG(t, tns, conf, nil, nil, nil)
	testResults(t, suite, thr, n, results)

	for i, t := range tns {
		t.res = results[i]
	}
	testResults(t, suite, thr, n, results)

	// we setup now the second group with higher node count and higher threshold
	// and we remove one node from the previous group
	nodesToAdd := 5
	newN := n - 1 + nodesToAdd   // we remove one old node
	newT := thr + nodesToAdd - 1 // set the threshold to accept one offline new node
	var newTns = make([]*TestNode, 0, newN)
	// remove a random node from the previous group
	offlineToRemove := uint32(rand.Intn(n))
	for _, node := range tns {
		if node.Index == offlineToRemove {
			continue
		}
		newTns = append(newTns, node)
		t.Logf("Added old node newTns[%d].Index = %d\n", len(newTns), newTns[len(newTns)-1].Index)
	}
	// we also mess up with indexing here
	newSkipped := 2
	t.Logf("skippedIndex: %d, newSkipped: %d\n", skippedIndex, newSkipped)
	for i := 0; i <= nodesToAdd; i++ {
		if i == newSkipped {
			continue // gonna get filled up at last iteration
		}
		// we start at n to be sure we dont overlap with previous indices
		newTns = append(newTns, NewTestNode(suite, n+i))
		t.Logf("Added new node newTns[%d].Index = %d\n", len(newTns), newTns[len(newTns)-1].Index)
	}
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

	var deals []*DealBundle
	for _, node := range newTns {
		if node.res == nil {
			// new members don't issue deals
			continue
		}
		d, err := node.dkg.Deals()
		require.NoError(t, err)
		deals = append(deals, d)
	}

	var responses []*ResponseBundle
	for _, node := range newTns {
		resp, err := node.dkg.ProcessDeals(deals)
		require.NoError(t, err)
		require.NotNil(t, resp)
		// a node from the old group is not present so there should be
		// some responses !
		responses = append(responses, resp)
	}
	// all nodes in the new group should have reported an error
	require.Equal(t, newN, len(responses))

	results = nil
	for _, node := range newTns {
		res, just, err := node.dkg.ProcessResponses(responses)
		// we should have enough old nodes available to get a successful DKG
		require.NoError(t, err)
		require.Nil(t, res)
		// since the last old node is absent he can't give any justifications
		require.Nil(t, just)
	}

	for _, node := range newTns {
		res, err := node.dkg.ProcessJustifications(nil)
		require.NoError(t, err)
		require.NotNil(t, res)
		results = append(results, res)
	}
	testResults(t, suite, newT, newN, results)

}
func TestDKGFull(t *testing.T) {
	n := 5
	thr := n
	suite := edwards25519.NewBlakeSHA256Ed25519()
	tns := GenerateTestNodes(suite, n)
	list := NodesFromTest(tns)
	conf := Config{
		Suite:     suite,
		NewNodes:  list,
		Threshold: thr,
		Auth:      schnorr.NewScheme(suite),
	}

	results := RunDKG(t, tns, conf, nil, nil, nil)
	testResults(t, suite, thr, n, results)
}

func TestSelfEvictionShareHolder(t *testing.T) {
	n := 5
	thr := 4
	var suite = bn256.NewSuiteG2()
	var sigSuite = bn256.NewSuiteG1()
	tns := GenerateTestNodes(suite, n)
	list := NodesFromTest(tns)
	conf := Config{
		Suite:     suite,
		NewNodes:  list,
		Threshold: thr,
		Auth:      schnorr.NewScheme(suite),
	}

	results := RunDKG(t, tns, conf, nil, nil, nil)
	for i, t := range tns {
		t.res = results[i]
	}
	testResults(t, suite, thr, n, results)

	// create a partial signature with the share now and make sure the partial
	// signature is verifiable and then *not* verifiable after the resharing
	oldShare := results[0].Key.Share
	msg := []byte("Hello World")
	scheme := tbls.NewThresholdSchemeOnG1(sigSuite)
	oldPartial, err := scheme.Sign(oldShare, msg)
	require.NoError(t, err)
	poly := share.NewPubPoly(suite, suite.Point().Base(), results[0].Key.Commits)
	require.NoError(t, scheme.VerifyPartial(poly, msg, oldPartial))

	// we setup now the second group with higher node count and higher threshold
	// and we remove one node from the previous group
	newN := n + 5
	newT := thr + 4
	var newTns = make([]*TestNode, n)
	copy(newTns, tns)
	newNode := newN - n
	for i := 0; i < newNode; i++ {
		newTns = append(newTns, NewTestNode(suite, n+1+i))
	}
	newIndexToEvict := newTns[len(newTns)-1].Index
	newList := NodesFromTest(newTns)
	newConf := &Config{
		Suite:        suite,
		NewNodes:     newList,
		OldNodes:     list,
		Threshold:    newT,
		OldThreshold: thr,
		FastSync:     true,
		Auth:         schnorr.NewScheme(suite),
	}

	SetupReshareNodes(newTns, newConf, tns[0].res.Key.Commits)

	var deals []*DealBundle
	for _, node := range newTns {
		if node.res == nil {
			// new members don't issue deals
			continue
		}
		d, err := node.dkg.Deals()
		require.NoError(t, err)
		deals = append(deals, d)
	}

	var responses []*ResponseBundle
	for _, node := range newTns {
		resp, err := node.dkg.ProcessDeals(deals)
		require.NoError(t, err)
		if node.Index == newIndexToEvict {
			// we insert a bad session ID for example so this new recipient should be evicted
			resp.SessionID = []byte("That looks so wrong")
		}
		responses = append(responses, resp)
	}
	require.True(t, len(responses) > 0)

	results = nil
	for _, node := range newTns {
		_, _, err := node.dkg.ProcessResponses(responses)
		require.True(t, contains(node.dkg.evictedHolders, newIndexToEvict))
		if node.Index == newIndexToEvict {
			require.Error(t, err)
			continue
		}
		require.NoError(t, err)
	}
}

func TestDKGResharing(t *testing.T) {
	n := 5
	thr := 4
	var suite = bn256.NewSuiteG2()
	var sigSuite = bn256.NewSuiteG1()
	tns := GenerateTestNodes(suite, n)
	list := NodesFromTest(tns)
	conf := Config{
		Suite:     suite,
		NewNodes:  list,
		Threshold: thr,
		Auth:      schnorr.NewScheme(suite),
	}

	results := RunDKG(t, tns, conf, nil, nil, nil)
	for i, t := range tns {
		t.res = results[i]
	}
	testResults(t, suite, thr, n, results)

	// create a partial signature with the share now and make sure the partial
	// signature is verifiable and then *not* verifiable after the resharing
	oldShare := results[0].Key.Share
	msg := []byte("Hello World")
	scheme := tbls.NewThresholdSchemeOnG1(sigSuite)
	oldPartial, err := scheme.Sign(oldShare, msg)
	require.NoError(t, err)
	poly := share.NewPubPoly(suite, suite.Point().Base(), results[0].Key.Commits)
	require.NoError(t, scheme.VerifyPartial(poly, msg, oldPartial))

	// we setup now the second group with higher node count and higher threshold
	// and we remove one node from the previous group
	newN := n + 5
	newT := thr + 4
	var newTns = make([]*TestNode, newN)
	// remove the last node from the previous group
	offline := 1
	copy(newTns, tns[:n-offline])
	// + offline because we fill the gap of the offline nodes by new nodes
	newNode := newN - n + offline
	for i := 0; i < newNode; i++ {
		//  new node can have the same index as a previous one, separation is made
		newTns[n-1+i] = NewTestNode(suite, n-1+i)
	}
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

	var deals []*DealBundle
	for _, node := range newTns {
		if node.res == nil {
			// new members don't issue deals
			continue
		}
		d, err := node.dkg.Deals()
		require.NoError(t, err)
		deals = append(deals, d)
	}

	var responses []*ResponseBundle
	for _, node := range newTns {
		resp, err := node.dkg.ProcessDeals(deals)
		require.NoError(t, err)
		if resp != nil {
			// last node from the old group is not present so there should be
			// some responses !
			responses = append(responses, resp)
		}
	}
	require.True(t, len(responses) > 0)

	results = nil
	for _, node := range newTns {
		res, just, err := node.dkg.ProcessResponses(responses)
		require.NoError(t, err)
		require.Nil(t, res)
		// since the last old node is absent he can't give any justifications
		require.Nil(t, just)
	}

	for _, node := range newTns {
		res, err := node.dkg.ProcessJustifications(nil)
		require.NoError(t, err)
		require.NotNil(t, res)
		results = append(results, res)
	}
	testResults(t, suite, newT, newN, results)

	// test a tbls signature is correct
	newShare := results[0].Key.Share
	newPartial, err := scheme.Sign(newShare, msg)
	require.NoError(t, err)
	newPoly := share.NewPubPoly(suite, suite.Point().Base(), results[0].Key.Commits)
	require.NoError(t, scheme.VerifyPartial(newPoly, msg, newPartial))
	// test we can not verify the old partial with the new public polynomial
	require.Error(t, scheme.VerifyPartial(poly, msg, newPartial))
}

func TestDKGThreshold(t *testing.T) {
	n := 5
	thr := 4
	suite := edwards25519.NewBlakeSHA256Ed25519()
	tns := GenerateTestNodes(suite, n)
	list := NodesFromTest(tns)
	conf := Config{
		Suite:     suite,
		NewNodes:  list,
		Threshold: thr,
		Auth:      schnorr.NewScheme(suite),
	}

	dm := func(deals []*DealBundle) []*DealBundle {
		// we make first dealer absent
		deals = deals[1:]
		require.Len(t, deals, n-1)
		// we make the second dealer creating a invalid share for 3rd participant
		deals[0].Deals[2].EncryptedShare = []byte("Another one bites the dust")
		return deals
	}
	rm := func(resp []*ResponseBundle) []*ResponseBundle {
		for _, bundle := range resp {
			// first dealer should not see anything bad
			require.NotEqual(t, 0, bundle.ShareIndex)
		}
		// we must find at least a complaint about node 0
		require.True(t, IsDealerIncluded(resp, 0))
		// if we are checking responses from node 2, then it must also
		// include a complaint for node 1
		require.True(t, IsDealerIncluded(resp, 1))
		return resp
	}
	jm := func(justs []*JustificationBundle) []*JustificationBundle {
		var found0 bool
		var found1 bool
		for _, bundle := range justs {
			found0 = found0 || bundle.DealerIndex == 0
			found1 = found1 || bundle.DealerIndex == 1
		}
		require.True(t, found0 && found1)
		return justs
	}
	results := RunDKG(t, tns, conf, dm, rm, jm)
	var filtered = results[:0]
	for _, n := range tns {
		if 0 == n.Index {
			// node 0 is excluded by all others since he didn't even provide a
			// deal at the first phase,i.e. it didn't even provide a public
			// polynomial at the first phase.
			continue
		}
		for _, res := range results {
			if res.Key.Share.I != int(n.Index) {
				continue
			}
			for _, nodeQual := range res.QUAL {
				require.NotEqual(t, uint32(0), nodeQual.Index)
			}
			filtered = append(filtered, res)
		}
	}
	testResults(t, suite, thr, n, filtered)
}

func TestDKGResharingFast(t *testing.T) {
	n := 6
	thr := 4
	var suite = bn256.NewSuiteG2()
	var sigSuite = bn256.NewSuiteG1()
	tns := GenerateTestNodes(suite, n)
	list := NodesFromTest(tns)
	conf := Config{
		Suite:     suite,
		NewNodes:  list,
		Threshold: thr,
		Auth:      schnorr.NewScheme(suite),
	}
	SetupNodes(tns, &conf)

	var deals []*DealBundle
	for _, node := range tns {
		d, err := node.dkg.Deals()
		require.NoError(t, err)
		deals = append(deals, d)
	}

	for _, node := range tns {
		resp, err := node.dkg.ProcessDeals(deals)
		require.NoError(t, err)
		// for a full perfect dkg there should not be any complaints
		require.Nil(t, resp)
	}

	var results []*Result
	for _, node := range tns {
		// we give no responses
		res, just, err := node.dkg.ProcessResponses(nil)
		require.NoError(t, err)
		require.Nil(t, just)
		require.NotNil(t, res)
		results = append(results, res)
		node.res = res
	}
	testResults(t, suite, thr, n, results)

	// create a partial signature with the share now and make sure the partial
	// signature is verifiable and then *not* verifiable after the resharing
	oldShare := results[0].Key.Share
	msg := []byte("Hello World")
	scheme := tbls.NewThresholdSchemeOnG1(sigSuite)
	oldPartial, err := scheme.Sign(oldShare, msg)
	require.NoError(t, err)
	poly := share.NewPubPoly(suite, suite.Point().Base(), results[0].Key.Commits)
	require.NoError(t, scheme.VerifyPartial(poly, msg, oldPartial))

	// we setup now the second group with higher node count and higher threshold
	// and we remove one node from the previous group
	newN := n + 5
	newT := thr + 4
	var newTns = make([]*TestNode, newN)
	// remove the last node from the previous group
	offline := 1
	copy(newTns, tns[:n-offline])
	// + offline because we fill the gap of the offline nodes by new nodes
	newNode := newN - n + offline
	for i := 0; i < newNode; i++ {
		//  new node can have the same index as a previous one, separation is made
		newTns[n-1+i] = NewTestNode(suite, n-1+i)
	}
	newList := NodesFromTest(newTns)
	// key from the previous and new group which is registered in the
	// group but wont participate
	p := 1
	skipKey := list[p].Public
	var skipNew Index
	for _, n := range newList {
		if n.Public.Equal(skipKey) {
			skipNew = n.Index
		}
	}
	fmt.Println("skipping old index: ", list[p].Index, "public key", skipKey, "newIdx", skipNew)

	newConf := &Config{
		Suite:        suite,
		NewNodes:     newList,
		OldNodes:     list,
		Threshold:    newT,
		OldThreshold: thr,
		Auth:         schnorr.NewScheme(suite),
		FastSync:     true,
	}

	SetupReshareNodes(newTns, newConf, tns[0].res.Key.Commits)

	deals = nil
	for _, node := range newTns {
		if node.res == nil {
			// new members don't issue deals
			continue
		}
		if node.Public.Equal(skipKey) {
			continue
		}
		d, err := node.dkg.Deals()
		require.NoError(t, err)
		deals = append(deals, d)
	}

	var responses []*ResponseBundle
	for _, node := range newTns {
		if node.Public.Equal(skipKey) {
			continue
		}
		resp, err := node.dkg.ProcessDeals(deals)
		require.NoError(t, err)

		if resp != nil {
			// last node from the old group is not present so there should be
			// some responses !
			responses = append(responses, resp)
		}
	}
	require.True(t, len(responses) > 0)

	results = nil
	var justifs []*JustificationBundle
	for _, node := range newTns {
		if node.Public.Equal(skipKey) {
			continue
		}
		res, just, err := node.dkg.ProcessResponses(responses)
		require.NoError(t, err)
		require.Nil(t, res)
		if node.res == nil {
			// new members don't issue justifications
			continue
		}
		require.NotNil(t, just.Justifications)
		require.Equal(t, just.Justifications[0].ShareIndex, skipNew)
		justifs = append(justifs, just)
	}

	for _, node := range newTns {
		if node.Public.Equal(skipKey) {
			continue
		}
		res, err := node.dkg.ProcessJustifications(justifs)
		require.NoError(t, err)
		require.NotNil(t, res)
		results = append(results, res)
	}

	for _, res := range results {
		for _, n := range res.QUAL {
			require.False(t, n.Public.Equal(skipKey))
		}
	}
	testResults(t, suite, newT, newN, results)

	// test a tbls signature is correct
	newShare := results[0].Key.Share
	newPartial, err := scheme.Sign(newShare, msg)
	require.NoError(t, err)
	newPoly := share.NewPubPoly(suite, suite.Point().Base(), results[0].Key.Commits)
	require.NoError(t, scheme.VerifyPartial(newPoly, msg, newPartial))
	// test we can not verify the old partial with the new public polynomial
	require.Error(t, scheme.VerifyPartial(poly, msg, newPartial))
}

func TestDKGFullFast(t *testing.T) {
	n := 5
	thr := n
	suite := edwards25519.NewBlakeSHA256Ed25519()
	tns := GenerateTestNodes(suite, n)
	list := NodesFromTest(tns)
	conf := Config{
		FastSync:  true,
		Suite:     suite,
		NewNodes:  list,
		Threshold: thr,
		Auth:      schnorr.NewScheme(suite),
	}

	results := RunDKG(t, tns, conf, nil, nil, nil)
	testResults(t, suite, thr, n, results)
}

func TestDKGNonceInvalid(t *testing.T) {
	n := 5
	thr := n
	suite := edwards25519.NewBlakeSHA256Ed25519()
	tns := GenerateTestNodes(suite, n)
	list := NodesFromTest(tns)
	conf := &Config{
		FastSync:  true,
		Suite:     suite,
		NewNodes:  list,
		Threshold: thr,
		Auth:      schnorr.NewScheme(suite),
	}
	nonce := GetNonce()
	conf.Nonce = nonce
	conf.Longterm = tns[0].Private
	conf.Nonce = nonce
	dkg, err := NewDistKeyHandler(conf)
	require.NoError(t, err)
	require.NotNil(t, dkg)

	conf.Nonce = []byte("that's some bad nonce")
	dkg, err = NewDistKeyHandler(conf)
	require.Error(t, err)
	require.Nil(t, dkg)
}

func TestDKGAbsentAuth(t *testing.T) {
	n := 5
	thr := n
	suite := edwards25519.NewBlakeSHA256Ed25519()
	tns := GenerateTestNodes(suite, n)
	list := NodesFromTest(tns)
	conf := &Config{
		FastSync:  true,
		Suite:     suite,
		NewNodes:  list,
		Threshold: thr,
		Nonce:     GetNonce(),
		Longterm:  tns[0].Private,
	}
	dkg, err := NewDistKeyHandler(conf)
	require.Error(t, err)
	require.Nil(t, dkg)

	conf.Auth = schnorr.NewScheme(suite)
	dkg, err = NewDistKeyHandler(conf)
	require.NoError(t, err)
	require.NotNil(t, dkg)
}

func TestDKGNonceInvalidEviction(t *testing.T) {
	n := 7
	thr := 4
	suite := edwards25519.NewBlakeSHA256Ed25519()
	tns := GenerateTestNodes(suite, n)
	list := NodesFromTest(tns)
	conf := Config{
		Suite:     suite,
		NewNodes:  list,
		Threshold: thr,
		Auth:      schnorr.NewScheme(suite),
	}

	genPublic := func() []kyber.Point {
		points := make([]kyber.Point, thr)
		for i := 0; i < thr; i++ {
			points[i] = suite.Point().Pick(random.New())
		}
		return points
	}

	dm := func(deals []*DealBundle) []*DealBundle {
		deals[0].SessionID = []byte("Beat It")
		require.Equal(t, deals[0].DealerIndex, Index(0))
		// change the public polynomial so it trigggers a response and a
		// justification
		deals[1].Public = genPublic()
		require.Equal(t, deals[1].DealerIndex, Index(1))
		return deals
	}
	rm := func(resp []*ResponseBundle) []*ResponseBundle {
		for _, bundle := range resp {
			for _, r := range bundle.Responses {
				// he's evicted so there's not even a complaint
				require.NotEqual(t, 0, r.DealerIndex)
			}
			if bundle.ShareIndex == 2 {
				bundle.SessionID = []byte("Billie Jean")
			}
		}
		return resp
	}
	jm := func(just []*JustificationBundle) []*JustificationBundle {
		require.Len(t, just, 1)
		just[0].SessionID = []byte("Free")
		return just
	}

	results := RunDKG(t, tns, conf, dm, rm, jm)
	// make sure the first, second, and third node are not here
	isEvicted := func(i Index) bool {
		return i == 0 || i == 1 || i == 2
	}
	filtered := results[:0]
	for _, r := range results {
		if isEvicted(Index(r.Key.Share.I)) {
			continue
		}
		require.NotContains(t, r.QUAL, Index(0))
		require.NotContains(t, r.QUAL, Index(1))
		require.NotContains(t, r.QUAL, Index(2))
		filtered = append(filtered, r)
	}
	testResults(t, suite, thr, n, filtered)
}

func TestDKGInvalidResponse(t *testing.T) {
	n := 6
	thr := 3
	suite := edwards25519.NewBlakeSHA256Ed25519()
	tns := GenerateTestNodes(suite, n)
	list := NodesFromTest(tns)
	conf := Config{
		Suite:     suite,
		NewNodes:  list,
		Threshold: thr,
		Auth:      schnorr.NewScheme(suite),
	}
	SetupNodes(tns, &conf)

	var deals []*DealBundle
	for _, node := range tns {
		d, err := node.dkg.Deals()
		require.NoError(t, err)
		deals = append(deals, d)
	}
	// we make first dealer absent
	deals = deals[1:]
	require.Len(t, deals, n-1)

	var respBundles []*ResponseBundle
	for _, node := range tns {
		resp, err := node.dkg.ProcessDeals(deals)
		require.NoError(t, err)
		if node.Index == 0 {
			// first dealer should not see anything bad
			require.Nil(t, resp)
		} else {
			require.NotNil(t, resp, " node index %d: resp %v", node.Index, resp)
			respBundles = append(respBundles, resp)
		}
	}

	// trigger invalid dealer index
	respBundles[1].Responses[0].DealerIndex = 1000
	// trigger invalid status: in normal mode, no success should ever be sent
	respBundles[2].Responses[0].Status = Success

	var justifs []*JustificationBundle
	for i, node := range tns {
		res, just, err := node.dkg.ProcessResponses(respBundles)
		if i == 0 {
			// node 0 was absent so there is more than a threshold of nodes
			// that make the complaint so he's being evicted
			require.Error(t, err)
			continue
		}
		require.NoError(t, err)
		require.Nil(t, res)
		if just != nil {
			require.NotNil(t, just)
			justifs = append(justifs, just)
		}
	}

	var results []*Result
	for _, node := range tns {
		if node.Index == 0 || node.Index == 2 || node.Index == 3 {
			// node 0 is excluded by all others since he didn't even provide a
			// deal at the first phase,i.e. it didn't even provide a public
			// polynomial at the first phase.
			// node 2 and 3 are excluded as well because they didn't provide a
			// valid response
			continue
		}
		res, err := node.dkg.ProcessJustifications(justifs)
		require.NoError(t, err)
		require.NotNil(t, res)
		for _, nodeQual := range res.QUAL {
			require.NotEqual(t, uint32(0), nodeQual.Index)
			// node 2 and 3 gave invalid response
			require.NotEqual(t, uint32(2), nodeQual.Index)
			require.NotEqual(t, uint32(3), nodeQual.Index)
		}
		results = append(results, res)
	}
	testResults(t, suite, thr, n, results)
}

func TestDKGTooManyComplaints(t *testing.T) {
	n := 5
	thr := 3
	suite := edwards25519.NewBlakeSHA256Ed25519()
	tns := GenerateTestNodes(suite, n)
	list := NodesFromTest(tns)
	conf := Config{
		Suite:     suite,
		NewNodes:  list,
		Threshold: thr,
		Auth:      schnorr.NewScheme(suite),
	}

	dm := func(deals []*DealBundle) []*DealBundle {
		// we make the second dealer creating a invalid share for too many
		// participants
		for i := 0; i <= thr; i++ {
			deals[0].Deals[i].EncryptedShare = []byte("Another one bites the dust")
		}
		return deals
	}
	results := RunDKG(t, tns, conf, dm, nil, nil)
	var filtered = results[:0]
	for _, n := range tns {
		if 0 == n.Index {
			// node 0 is excluded by all others since he didn't even provide a
			// deal at the first phase,i.e. it didn't even provide a public
			// polynomial at the first phase.
			continue
		}
		for _, res := range results {
			if res.Key.Share.I != int(n.Index) {
				continue
			}
			for _, nodeQual := range res.QUAL {
				require.NotEqual(t, uint32(0), nodeQual.Index)
			}
			filtered = append(filtered, res)
		}
	}
	testResults(t, suite, thr, n, filtered)
}

func TestConfigDuplicate(t *testing.T) {
	n := 5
	nodes := make([]Node, n)
	for i := 0; i < n; i++ {
		nodes[i] = Node{
			Index:  Index(i),
			Public: nil,
		}
	}
	nodes[2].Index = nodes[1].Index
	c := &Config{
		OldNodes: nodes,
	}
	require.Error(t, c.CheckForDuplicates())
	c = &Config{
		NewNodes: nodes,
	}
	require.Error(t, c.CheckForDuplicates())
}

func TestMinimumT(t *testing.T) {
	tests := []struct {
		input  int
		output int
	}{
		{10, 6},
		{6, 4},
		{4, 3},
		{3, 2},
		{2, 2},
		{7, 4},
		{8, 5},
		{9, 5},
	}
	for _, test := range tests {
		in := test.input
		exp := test.output
		t.Run(fmt.Sprintf("DKG-MininumT-%d", test.input), func(t *testing.T) {
			if MinimumT(in) != exp {
				t.Fail()
			}
		})
	}
}
