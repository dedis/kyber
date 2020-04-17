package dkg

import (
	"testing"

	"github.com/drand/kyber"
	"github.com/drand/kyber/group/edwards25519"
	"github.com/drand/kyber/share"
	"github.com/drand/kyber/util/random"
	"github.com/stretchr/testify/require"
)

type TestNode struct {
	Index   uint32
	Private kyber.Scalar
	Public  kyber.Point
	dkg     *DistKeyGenerator
}

func GenerateTestNodes(s Suite, n int) []*TestNode {
	tns := make([]*TestNode, n)
	for i := 0; i < n; i++ {
		private := s.Scalar().Pick(random.New())
		public := s.Point().Mul(private, nil)
		tns[i] = &TestNode{
			Index:   uint32(i),
			Private: private,
			Public:  public,
		}
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
	for _, n := range nodes {
		c2 := *c
		c2.Longterm = n.Private
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
	}

	testResults(t, suite, thr, n, results)
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
	// we make the second dealer creating a invalid share for 3rd participant
	deals[0].Deals[2].EncryptedShare = []byte("Another one bites the dust")

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
	// we must find at least a complaint about node 0
	require.True(t, IsDealerIncluded(respBundles, 0))
	// if we are checking responses from node 2, then it must also
	// include a complaint for node 1
	require.True(t, IsDealerIncluded(respBundles, 1))

	var justifs []*JustificationBundle
	for _, node := range tns {
		res, just, err := node.dkg.ProcessResponses(respBundles)
		require.NoError(t, err)
		require.Nil(t, res)
		if node.Index == 0 || node.Index == 1 {
			require.NotNil(t, just)
			justifs = append(justifs, just)
		}
	}

	var results []*Result
	for _, node := range tns {
		if node.Index == 0 {
			// node 0 is excluded by all others since he didn't even provide a
			// deal at the first phase,i.e. it didn't even provide a public
			// polynomial at the first phase.
			continue
		}
		res, err := node.dkg.ProcessJustifications(justifs)
		require.NoError(t, err)
		require.NotNil(t, res)
		results = append(results, res)
	}
	testResults(t, suite, thr, n, results)
}
