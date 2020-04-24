package examples

import (
	"testing"

	"github.com/stretchr/testify/require"
	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/kyber/v3/group/edwards25519"
	"go.dedis.ch/kyber/v3/share"
	dkg "go.dedis.ch/kyber/v3/share/dkg/pedersen"
)

var suite = edwards25519.NewBlakeSHA256Ed25519()

/*
This example illustrates how to use the dkg/pedersen API to generate a public
key and its corresponding private key that is shared among nodes. It shows the
different phases that each node must perform in order to construct the private
shares that will form the final private key. The example uses 3 nodes and shows
the "happy" path where each node does its job correctly.
*/
func Test_Example_DKG(t *testing.T) {

	// number of nodes
	n := 3

	type node struct {
		dkg         *dkg.DistKeyGenerator
		pubKey      kyber.Point
		privKey     kyber.Scalar
		deals       []*dkg.Deal
		resps       []*dkg.Response
		secretShare *share.PriShare
	}

	nodes := make([]*node, n)
	pubKeys := make([]kyber.Point, n)

	// 1. Init the nodes
	for i := 0; i < n; i++ {
		privKey := suite.Scalar().Pick(suite.RandomStream())
		pubKey := suite.Point().Mul(privKey, nil)
		pubKeys[i] = pubKey
		nodes[i] = &node{
			pubKey:  pubKey,
			privKey: privKey,
			deals:   make([]*dkg.Deal, 0),
			resps:   make([]*dkg.Response, 0),
		}
	}

	// 2. Create the DKGs on each node
	for i, node := range nodes {
		dkg, err := dkg.NewDistKeyGenerator(suite, nodes[i].privKey, pubKeys, n)
		require.NoError(t, err)
		node.dkg = dkg
	}

	// 3. Each node sends its Deals to the other nodes
	for _, node := range nodes {
		deals, err := node.dkg.Deals()
		require.NoError(t, err)
		for i, deal := range deals {
			nodes[i].deals = append(nodes[i].deals, deal)
		}
	}

	// 4. Process the Deals on each node and send the responses to the other
	// nodes
	for i, node := range nodes {
		for _, deal := range node.deals {
			resp, err := node.dkg.ProcessDeal(deal)
			require.NoError(t, err)
			for j, otherNode := range nodes {
				if j == i {
					continue
				}
				otherNode.resps = append(otherNode.resps, resp)
			}
		}
	}

	// 5. Process the responses on each node
	for _, node := range nodes {
		for _, resp := range node.resps {
			_, err := node.dkg.ProcessResponse(resp)
			require.NoError(t, err)
			// err = node.dkg.ProcessJustification(justification)
			// require.NoError(t, err)
		}
	}

	// 6. Check and print the qualified shares
	for _, node := range nodes {
		require.True(t, node.dkg.Certified())
		require.Equal(t, 3, len(node.dkg.QualifiedShares()))
		require.Equal(t, 3, len(node.dkg.QUAL()))
		t.Log("qualified shares:", node.dkg.QualifiedShares())
		t.Log("QUAL", node.dkg.QUAL())
	}

	// 7. Get the secret shares and public key
	shares := make([]*share.PriShare, n)
	var publicKey kyber.Point
	for i, node := range nodes {
		distrKey, err := node.dkg.DistKeyShare()
		require.NoError(t, err)
		shares[i] = distrKey.PriShare()
		publicKey = distrKey.Public()
		node.secretShare = distrKey.PriShare()
		t.Log("distributed public key:", publicKey)
		t.Log("distributed private share:", shares[i])
	}

	// 8. Encrypt a secret with the public key and decrypt it with the
	// reconstructed shared secret key. Reconstructing the shared secret key in
	// not something we should do as it gives the power to decrpy any further
	// messages encrypted with the shared public key. Step 9 shows how to
	// decrypt the message by gathering partial decryptions from the nodes.
	message := []byte("Hello world")
	secretKey, err := share.RecoverSecret(suite, shares, n, n)
	require.NoError(t, err)
	K, C, remainder := ElGamalEncrypt(suite, publicKey, message)
	require.Equal(t, 0, len(remainder))
	decryptedMessage, err := ElGamalDecrypt(suite, secretKey, K, C)
	require.Equal(t, message, decryptedMessage)

	// 9. Second version, each node provide only a partial decryption
	// 9.1 each node sends its partial decryption
	partials := make([]kyber.Point, n)
	for i, node := range nodes {
		S := suite.Point().Mul(node.secretShare.V, K)
		partials[i] = suite.Point().Sub(C, S)
	}

	// 9.2 create the public shares to reconstruct the public commitment
	pubShares := make([]*share.PubShare, n)
	for i := range nodes {
		pubShares[i] = &share.PubShare{
			I: i, V: partials[i],
		}
	}

	// 9.3 reconstruct the public commitment, which contains the decrypted
	// message
	res, err := share.RecoverCommit(suite, pubShares, n, n)
	require.NoError(t, err)
	decryptedMessage, err = res.Data()
	require.NoError(t, err)
	require.Equal(t, message, decryptedMessage)
}
