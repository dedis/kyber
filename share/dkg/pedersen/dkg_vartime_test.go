//go:build !constantTime

package dkg

import (
	"testing"

	"github.com/stretchr/testify/require"
	"go.dedis.ch/kyber/v4/pairing/bn256"
	"go.dedis.ch/kyber/v4/share"
	"go.dedis.ch/kyber/v4/sign/schnorr"
	"go.dedis.ch/kyber/v4/sign/tbls"
)

func TestDKGResharingFast(t *testing.T) {
	n := uint32(6)
	thr := uint32(4)
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
	offline := uint32(1)
	copy(newTns, tns[:n-offline])
	// + offline because we fill the gap of the offline nodes by new nodes
	newNode := newN - n + offline
	for i := uint32(0); i < newNode; i++ {
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
	t.Log("skipping old index: ", list[p].Index, "public key", skipKey, "newIdx", skipNew)

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

func TestSelfEvictionShareHolder(t *testing.T) {
	n := uint32(5)
	thr := uint32(4)
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
	for i := uint32(0); i < newNode; i++ {
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
	n := uint32(5)
	thr := uint32(4)
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
	offline := uint32(1)
	copy(newTns, tns[:n-offline])
	// + offline because we fill the gap of the offline nodes by new nodes
	newNode := newN - n + offline
	for i := uint32(0); i < newNode; i++ {
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
