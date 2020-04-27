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
		t.Log("new distributed public key:", publicKey)
	}

	// 8. Variant A - Encrypt a secret with the public key and decrypt it with
	// the reconstructed shared secret key. Reconstructing the shared secret key
	// in not something we should do as it gives the power to decrypt any
	// further messages encrypted with the shared public key. For this we show
	// in variant B how to make nodes send back partial decryptions instead of
	// their shares. In variant C the nodes return partial decrpytions that are
	// encrypted under a provided public key.
	message := []byte("Hello world")
	secretKey, err := share.RecoverSecret(suite, shares, n, n)
	require.NoError(t, err)
	K, C, remainder := ElGamalEncrypt(suite, publicKey, message)
	require.Equal(t, 0, len(remainder))
	decryptedMessage, err := ElGamalDecrypt(suite, secretKey, K, C)
	require.Equal(t, message, decryptedMessage)

	// 8. Variant B - Each node provide only a partial decryption by sending its
	// public share. We then reconstruct the public commitment with those public
	// shares.
	partials := make([]kyber.Point, n)
	pubShares := make([]*share.PubShare, n)
	for i, node := range nodes {
		S := suite.Point().Mul(node.secretShare.V, K)
		partials[i] = suite.Point().Sub(C, S)
		pubShares[i] = &share.PubShare{
			I: i, V: partials[i],
		}
	}

	// Reconstruct the public commitment, which contains the decrypted message
	res, err := share.RecoverCommit(suite, pubShares, n, n)
	require.NoError(t, err)
	decryptedMessage, err = res.Data()
	require.NoError(t, err)
	require.Equal(t, message, decryptedMessage)

	// 8 Variant C - Nodes return a partial decryption under the encryption from
	// a public key. This is useful in case the decryption happens in public. In
	// that case the decrypted secret is never released in clear, but the secret
	// is revealed re-encrypted under the provided public key.
	//
	// Here is the crypto that happens in 3 phases:
	//
	// (1) Message encryption:
	//
	// r: random point
	// A: dkg public key
	// G: curve's generator
	// M: message to encrypt
	//
	// C = rA + M
	// U = rG
	//
	// (2) Node's partial decryption
	//
	// V: node's public re-encrypted share
	// o: node's private share
	// Q: client's public key (pG)
	//
	// V = oU + oQ
	//
	// (3) Message's decryption
	//
	// R: recovered commit (f(V1, V2, ...Vi))
	// p: client's private key
	// M': decrypted message
	//
	// M' = C - (R - pA)

	A := publicKey
	r := suite.Scalar().Pick(suite.RandomStream())
	M := suite.Point().Embed(message, suite.RandomStream())
	C = suite.Point().Add( // rA + M
		suite.Point().Mul(r, A), // rA
		M,
	)
	U := suite.Point().Mul(r, nil) // rG

	p := suite.Scalar().Pick(suite.RandomStream())
	Q := suite.Point().Mul(p, nil) // pG

	partials = make([]kyber.Point, n)
	pubShares = make([]*share.PubShare, n) // V1, V2, ...Vi
	for i, node := range nodes {
		v := suite.Point().Add( // oU + oQ
			suite.Point().Mul(node.secretShare.V, U), // oU
			suite.Point().Mul(node.secretShare.V, Q), // oQ
		)
		partials[i] = v
		pubShares[i] = &share.PubShare{
			I: i, V: partials[i],
		}
	}

	R, err := share.RecoverCommit(suite, pubShares, n, n) // R = f(V1, V2, ...Vi)
	require.NoError(t, err)

	decryptedPoint := suite.Point().Sub( // C - (R - pA)
		C,
		suite.Point().Sub( // R - pA
			R,
			suite.Point().Mul(p, A), // pA
		),
	)
	decryptedMessage, err = decryptedPoint.Data()
	require.NoError(t, err)
	require.Equal(t, decryptedMessage, message)

	// 9. The following shows a re-share of the dkg key, which will invalidates
	// the current shares on each node and produce a new public key. After that
	// steps 3, 4, 5 need to be done in order to get the new shares and public
	// key.
	for _, node := range nodes {
		share, err := node.dkg.DistKeyShare()
		require.NoError(t, err)
		c := &dkg.Config{
			Suite:        suite,
			Longterm:     node.privKey,
			OldNodes:     pubKeys,
			NewNodes:     pubKeys,
			Share:        share,
			Threshold:    n,
			OldThreshold: n,
		}
		newDkg, err := dkg.NewDistKeyHandler(c)
		require.NoError(t, err)
		node.dkg = newDkg
	}
}
