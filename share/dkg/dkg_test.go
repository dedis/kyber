package dkg

import (
	"github.com/drand/kyber"
	"github.com/drand/kyber/group/edwards25519"
	"github.com/drand/kyber/util/random"
	"github.com/stretchr/testify/require"
	"testing"
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

func TestDKGFull(t *testing.T) {
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

	for _, node := range tns {
		resp, err := node.dkg.ProcessDeals(deals)
		require.NoError(t, err)
		// for a full perfect dkg there should not be any complaints
		require.Nil(t, resp)
	}

	for _, node := range tns {
		// we give no responses
		res, just, err := node.dkg.ProcessResponses(nil)
		require.NoError(t, err)
		require.Nil(t, just)
		require.NotNil(t, res)
	}
}

func TestDKGThreshold(t *testing.T) {
	n := 6
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
	require.True(t, IsDealerIncluded(respBundles[1:1], 1))

	for _, node := range tns {
		// we give no responses
		res, just, err := node.dkg.ProcessResponses(respBundles)
		require.NoError(t, err)
		require.Nil(t, just)
		require.NotNil(t, res)
	}
}
