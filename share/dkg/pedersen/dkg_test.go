package dkg

import (
	"crypto/rand"
	"testing"

	"github.com/dedis/kyber"
	"github.com/dedis/kyber/group/edwards25519"
	"github.com/dedis/kyber/share"
	vss "github.com/dedis/kyber/share/vss/pedersen"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var suite = edwards25519.NewBlakeSHA256Ed25519()

var nbParticipants = 7

var partPubs []kyber.Point
var partSec []kyber.Scalar

var dkgs []*DistKeyGenerator
var dkgsReNew []*DistKeyGenerator

func init() {
	partPubs = make([]kyber.Point, nbParticipants)
	partSec = make([]kyber.Scalar, nbParticipants)
	for i := 0; i < nbParticipants; i++ {
		sec, pub := genPair()
		partPubs[i] = pub
		partSec[i] = sec
	}
	dkgs = dkgGen()
}

func TestDKGNewDistKeyGenerator(t *testing.T) {
	long := partSec[0]
	dkg, err := NewDistKeyGenerator(suite, long, partPubs, nbParticipants/2+1)
	assert.Nil(t, err)
	assert.NotNil(t, dkg.dealer)

	sec, _ := genPair()
	_, err = NewDistKeyGenerator(suite, sec, partPubs, nbParticipants/2+1)
	assert.Error(t, err)
}

func TestDKGDeal(t *testing.T) {
	dkg := dkgs[0]

	dks, err := dkg.DistKeyShare()
	assert.Error(t, err)
	assert.Nil(t, dks)

	deals, err := dkg.Deals()
	require.Nil(t, err)
	assert.Len(t, deals, nbParticipants-1)

	for i := range deals {
		assert.NotNil(t, deals[i])
		assert.Equal(t, uint32(0), deals[i].Index)
	}

	v, ok := dkg.verifiers[uint32(dkg.nidx)]
	assert.True(t, ok)
	assert.NotNil(t, v)
}

func TestDKGProcessDeal(t *testing.T) {
	dkgs = dkgGen()
	dkg := dkgs[0]
	deals, err := dkg.Deals()
	require.Nil(t, err)

	rec := dkgs[1]
	deal := deals[1]
	assert.Equal(t, int(deal.Index), 0)
	assert.Equal(t, 1, rec.nidx)

	// verifier don't find itself
	goodP := rec.c.NewNodes
	rec.c.NewNodes = make([]kyber.Point, 0)
	resp, err := rec.ProcessDeal(deal)
	assert.Nil(t, resp)
	assert.Error(t, err)
	rec.c.NewNodes = goodP

	// good deal
	resp, err = rec.ProcessDeal(deal)
	assert.NotNil(t, resp)
	assert.Equal(t, vss.StatusApproval, resp.Response.Status)
	assert.Nil(t, err)
	_, ok := rec.verifiers[deal.Index]
	require.True(t, ok)
	assert.Equal(t, uint32(0), resp.Index)

	// duplicate
	resp, err = rec.ProcessDeal(deal)
	assert.Nil(t, resp)
	assert.Error(t, err)

	// wrong index
	goodIdx := deal.Index
	deal.Index = uint32(nbParticipants + 1)
	resp, err = rec.ProcessDeal(deal)
	assert.Nil(t, resp)
	assert.Error(t, err)
	deal.Index = goodIdx

	// wrong deal
	goodSig := deal.Deal.Signature
	deal.Deal.Signature = randomBytes(len(deal.Deal.Signature))
	resp, err = rec.ProcessDeal(deal)
	assert.Nil(t, resp)
	assert.Error(t, err)
	deal.Deal.Signature = goodSig

}

func TestDKGProcessResponse(t *testing.T) {
	// first peer generates wrong deal
	// second peer processes it and returns a complaint
	// first peer process the complaint

	dkgs = dkgGen()
	dkg := dkgs[0]
	idxRec := 1
	rec := dkgs[idxRec]
	deal, err := dkg.dealer.PlaintextDeal(idxRec)
	require.Nil(t, err)

	// give a wrong deal
	goodSecret := deal.SecShare.V
	deal.SecShare.V = suite.Scalar().Zero()
	dd, err := dkg.Deals()
	encD := dd[idxRec]
	require.Nil(t, err)
	resp, err := rec.ProcessDeal(encD)
	assert.Nil(t, err)
	require.NotNil(t, resp)
	assert.Equal(t, vss.StatusComplaint, resp.Response.Status)
	deal.SecShare.V = goodSecret
	dd, _ = dkg.Deals()
	encD = dd[idxRec]

	// no verifier tied to Response
	v, ok := dkg.verifiers[0]
	require.NotNil(t, v)
	require.True(t, ok)
	require.NotNil(t, v)
	delete(dkg.verifiers, 0)
	j, err := dkg.ProcessResponse(resp)
	assert.Nil(t, j)
	assert.NotNil(t, err)
	dkg.verifiers[0] = v

	// invalid response
	goodSig := resp.Response.Signature
	resp.Response.Signature = randomBytes(len(goodSig))
	j, err = dkg.ProcessResponse(resp)
	assert.Nil(t, j)
	assert.Error(t, err)
	resp.Response.Signature = goodSig

	// valid complaint from our deal
	j, err = dkg.ProcessResponse(resp)
	assert.NotNil(t, j)
	assert.Nil(t, err)

	// valid complaint from another deal from another peer
	dkg2 := dkgs[2]
	require.Nil(t, err)
	// fake a wrong deal
	// deal20, err := dkg2.dealer.PlaintextDeal(0)
	// require.Nil(t, err)
	deal21, err := dkg2.dealer.PlaintextDeal(1)
	require.Nil(t, err)
	goodRnd21 := deal21.SecShare.V
	deal21.SecShare.V = suite.Scalar().Zero()
	deals2, err := dkg2.Deals()
	require.Nil(t, err)

	resp12, err := rec.ProcessDeal(deals2[idxRec])
	assert.NotNil(t, resp)
	assert.Equal(t, vss.StatusComplaint, resp12.Response.Status)

	deal21.SecShare.V = goodRnd21
	deals2, err = dkg2.Deals()
	require.Nil(t, err)

	// give it to the first peer
	// process dealer 2's deal
	r, err := dkg.ProcessDeal(deals2[0])
	assert.Nil(t, err)
	assert.NotNil(t, r)

	// process response from peer 1
	j, err = dkg.ProcessResponse(resp12)
	assert.Nil(t, j)
	assert.Nil(t, err)

	// Justification part:
	// give the complaint to the dealer
	j, err = dkg2.ProcessResponse(resp12)
	assert.Nil(t, err)
	assert.NotNil(t, j)

	// hack because all is local, and resp has been modified locally by dkg2's
	// dealer, the status has became "justified"
	resp12.Response.Status = vss.StatusComplaint
	err = dkg.ProcessJustification(j)
	assert.Nil(t, err)

	// remove verifiers
	v = dkg.verifiers[j.Index]
	delete(dkg.verifiers, j.Index)
	err = dkg.ProcessJustification(j)
	assert.Error(t, err)
	dkg.verifiers[j.Index] = v

}

func TestSetTimeout(t *testing.T) {
	dkgs = dkgGen()
	// full secret sharing exchange
	// 1. broadcast deals
	resps := make([]*Response, 0, nbParticipants*nbParticipants)
	for _, dkg := range dkgs {
		deals, err := dkg.Deals()
		require.Nil(t, err)
		for i, d := range deals {
			resp, err := dkgs[i].ProcessDeal(d)
			require.Nil(t, err)
			require.Equal(t, vss.StatusApproval, resp.Response.Status)
			resps = append(resps, resp)
		}
	}

	// 2. Broadcast responses
	for _, resp := range resps {
		for _, dkg := range dkgs {
			if !dkg.verifiers[resp.Index].EnoughApprovals() {
				// ignore messages about ourself
				if resp.Response.Index == uint32(dkg.nidx) {
					continue
				}
				j, err := dkg.ProcessResponse(resp)
				require.Nil(t, err)
				require.Nil(t, j)
			}
		}
	}

	// 3. make sure everyone has the same QUAL set
	for _, dkg := range dkgs {
		for _, dkg2 := range dkgs {
			require.False(t, dkg.isInQUAL(uint32(dkg2.nidx)))
		}
	}

	for _, dkg := range dkgs {
		dkg.SetTimeout()
	}

	for _, dkg := range dkgs {
		for _, dkg2 := range dkgs {
			require.True(t, dkg.isInQUAL(uint32(dkg2.nidx)))
		}
	}

}

func TestDistKeyShare(t *testing.T) {
	dkgs = dkgGen()
	fullExchange(t, dkgs)

	for _, dkg := range dkgs {
		assert.True(t, dkg.Certified())
	}
	// verify integrity of shares etc
	dkss := make([]*DistKeyShare, nbParticipants)
	var poly *share.PriPoly
	for i, dkg := range dkgs {
		dks, err := dkg.DistKeyShare()
		require.Nil(t, err)
		require.NotNil(t, dks)
		require.NotNil(t, dks.PrivatePoly)
		dkss[i] = dks
		assert.Equal(t, dkg.nidx, dks.Share.I)

		pripoly := share.CoefficientsToPriPoly(suite, dks.PrivatePoly)
		if poly == nil {
			poly = pripoly
			continue
		}
		poly, err = poly.Add(pripoly)
		require.NoError(t, err)
	}

	shares := make([]*share.PriShare, nbParticipants)
	for i, dks := range dkss {
		assert.True(t, checkDks(dks, dkss[0]), "dist key share not equal %d vs %d", dks.Share.I, 0)
		shares[i] = dks.Share
	}

	secret, err := share.RecoverSecret(suite, shares, nbParticipants, nbParticipants)
	assert.Nil(t, err)

	secretCoeffs := poly.Coefficients()
	require.Equal(t, secret.String(), secretCoeffs[0].String())

	commitSecret := suite.Point().Mul(secret, nil)
	assert.Equal(t, dkss[0].Public().String(), commitSecret.String())
}

func dkgGen() []*DistKeyGenerator {
	dkgs := make([]*DistKeyGenerator, nbParticipants)
	for i := 0; i < nbParticipants; i++ {
		dkg, err := NewDistKeyGenerator(suite, partSec[i], partPubs, vss.MinimumT(nbParticipants))
		if err != nil {
			panic(err)
		}
		dkgs[i] = dkg
	}
	return dkgs
}

func genPair() (kyber.Scalar, kyber.Point) {
	sc := suite.Scalar().Pick(suite.RandomStream())
	return sc, suite.Point().Mul(sc, nil)
}

func randomBytes(n int) []byte {
	var buff = make([]byte, n)
	_, _ = rand.Read(buff[:])
	return buff
}
func checkDks(dks1, dks2 *DistKeyShare) bool {
	if len(dks1.Commits) != len(dks2.Commits) {
		return false
	}
	for i, p := range dks1.Commits {
		if !p.Equal(dks2.Commits[i]) {
			return false
		}
	}
	return true
}

func fullExchange(t *testing.T, dkgs []*DistKeyGenerator) {
	// full secret sharing exchange
	// 1. broadcast deals
	resps := make([]*Response, 0, nbParticipants*nbParticipants)
	for _, dkg := range dkgs {
		deals, err := dkg.Deals()
		require.Nil(t, err)
		for i, d := range deals {
			resp, err := dkgs[i].ProcessDeal(d)
			require.Nil(t, err)
			require.Equal(t, vss.StatusApproval, resp.Response.Status)
			resps = append(resps, resp)
		}
	}
	// 2. Broadcast responses
	for _, resp := range resps {
		for _, dkg := range dkgs {
			// Ignore messages about ourselves
			if resp.Response.Index == uint32(dkg.nidx) {
				continue
			}
			j, err := dkg.ProcessResponse(resp)
			require.Nil(t, err)
			require.Nil(t, j)
		}
	}

	// 3. make sure everyone has the same QUAL set
	for _, dkg := range dkgs {
		for _, dkg2 := range dkgs {
			require.True(t, dkg.isInQUAL(uint32(dkg2.nidx)))
		}
	}
}

// Test resharing of a DKG to the same set of nodes
func TestDKGResharing(t *testing.T) {
	dkgs = dkgGen()
	fullExchange(t, dkgs)

	shares := make([]*DistKeyShare, len(dkgs))
	sshares := make([]*share.PriShare, len(dkgs))
	for i, dkg := range dkgs {
		share, err := dkg.DistKeyShare()
		require.NoError(t, err)
		shares[i] = share
		sshares[i] = shares[i].Share
	}
	// start resharing within the same group
	newDkgs := make([]*DistKeyGenerator, len(dkgs))
	var err error
	for i := range dkgs {
		c := &Config{
			Suite:    suite,
			Longterm: partSec[i],
			OldNodes: partPubs,
			NewNodes: partPubs,
			Share:    shares[i],
		}
		newDkgs[i], err = NewDistKeyHandler(c)
		require.NoError(t, err)
	}
	fullExchange(t, newDkgs)
	newShares := make([]*DistKeyShare, len(dkgs))
	newSShares := make([]*share.PriShare, len(dkgs))
	for i := range newDkgs {
		dks, err := newDkgs[i].DistKeyShare()
		require.NoError(t, err)
		newShares[i] = dks
		newSShares[i] = newShares[i].Share
	}
	// check
	// 1. shares are different between the two rounds
	// 2. shares reconstruct to the same secret
	// 3. public polynomial is different but for the first coefficient /public
	// key/
	// 1.
	for i := 0; i < len(dkgs); i++ {
		require.False(t, shares[i].Share.V.Equal(newShares[i].Share.V))
	}
	thr := vss.MinimumT(nbParticipants)
	// 2.
	oldSecret, err := share.RecoverSecret(suite, sshares, thr, nbParticipants)
	require.NoError(t, err)
	newSecret, err := share.RecoverSecret(suite, newSShares, thr, nbParticipants)
	require.NoError(t, err)
	require.Equal(t, oldSecret.String(), newSecret.String())
}

// Test resharing to a completely disjoint set of new nodes.
func TestDKGResharingNewNodes(t *testing.T) {
	dkgs = dkgGen()
	fullExchange(t, dkgs)

	shares := make([]*DistKeyShare, len(dkgs))
	sshares := make([]*share.PriShare, len(dkgs))
	for i, dkg := range dkgs {
		share, err := dkg.DistKeyShare()
		require.NoError(t, err)
		shares[i] = share
		sshares[i] = shares[i].Share
	}
	// start resharing to a different group
	oldN := nbParticipants
	oldT := len(shares[0].Commits)
	newN := oldN + 1
	newT := oldT + 1
	privates := make([]kyber.Scalar, newN)
	publics := make([]kyber.Point, newN)
	for i := 0; i < newN; i++ {
		privates[i] = suite.Scalar().Pick(suite.RandomStream())
		publics[i] = suite.Point().Mul(privates[i], nil)
	}

	// creating the old dkgs and new dkgs
	oldDkgs := make([]*DistKeyGenerator, oldN)
	newDkgs := make([]*DistKeyGenerator, newN)
	var err error
	for i := 0; i < oldN; i++ {
		c := &Config{
			Suite:     suite,
			Longterm:  partSec[i],
			OldNodes:  partPubs,
			NewNodes:  publics,
			Share:     shares[i],
			Threshold: newT,
		}
		oldDkgs[i], err = NewDistKeyHandler(c)
		require.NoError(t, err)
		require.False(t, oldDkgs[i].canReceive)
		require.True(t, oldDkgs[i].canIssue)
		require.True(t, oldDkgs[i].isResharing)
		require.False(t, oldDkgs[i].newPresent)
		require.Equal(t, oldDkgs[i].oidx, i)
	}

	for i := 0; i < newN; i++ {
		c := &Config{
			Suite:        suite,
			Longterm:     privates[i],
			OldNodes:     partPubs,
			NewNodes:     publics,
			PublicCoeffs: shares[0].Commits,
			Threshold:    newT,
		}
		newDkgs[i], err = NewDistKeyHandler(c)
		require.NoError(t, err)
		require.True(t, newDkgs[i].canReceive)
		require.False(t, newDkgs[i].canIssue)
		require.True(t, newDkgs[i].isResharing)
		require.True(t, newDkgs[i].newPresent)
		require.Equal(t, newDkgs[i].nidx, i)
	}

	// full secret sharing exchange
	// 1. broadcast deals
	resps := make([]*Response, 0, newN*newN)
	for _, dkg := range oldDkgs {
		deals, err := dkg.Deals()
		require.Nil(t, err)
		for i, d := range deals {
			resp, err := newDkgs[i].ProcessDeal(d)
			require.Nil(t, err)
			require.Equal(t, vss.StatusApproval, resp.Response.Status)
			resps = append(resps, resp)
		}
	}

	// 2. Broadcast responses
	for _, resp := range resps {
		for _, dkg := range oldDkgs {
			// Ignore messages about ourselves
			if resp.Response.Index == uint32(dkg.oidx) {
				continue
			}
			j, err := dkg.ProcessResponse(resp)
			require.Nil(t, err)
			require.Nil(t, j)
		}

		for _, dkg := range newDkgs {
			if resp.Response.Index == uint32(dkg.nidx) {
				continue
			}
			j, err := dkg.ProcessResponse(resp)
			require.Nil(t, err)
			require.Nil(t, j)
		}
	}

	// 3. make sure everyone has the same QUAL set
	for _, dkg := range newDkgs {
		for _, dkg2 := range oldDkgs {
			require.True(t, dkg.isInQUAL(uint32(dkg2.oidx)))
		}
	}

	newShares := make([]*DistKeyShare, newN)
	newSShares := make([]*share.PriShare, newN)
	for i := range newDkgs {
		dks, err := newDkgs[i].DistKeyShare()
		require.NoError(t, err)
		newShares[i] = dks
		newSShares[i] = newShares[i].Share
	}
	// check shares reconstruct to the same secret
	oldSecret, err := share.RecoverSecret(suite, sshares, oldT, oldN)
	require.NoError(t, err)
	newSecret, err := share.RecoverSecret(suite, newSShares, newT, newN)
	require.NoError(t, err)
	require.Equal(t, oldSecret.String(), newSecret.String())
}
