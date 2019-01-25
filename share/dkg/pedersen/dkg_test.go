package dkg

import (
	"crypto/rand"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/kyber/v3/group/edwards25519"
	"go.dedis.ch/kyber/v3/share"
	vss "go.dedis.ch/kyber/v3/share/vss/pedersen"
)

var suite = edwards25519.NewBlakeSHA256Ed25519()

const nbParticipants = 5

func generate() (partPubs []kyber.Point, partSec []kyber.Scalar, dkgs []*DistKeyGenerator) {
	partPubs = make([]kyber.Point, nbParticipants)
	partSec = make([]kyber.Scalar, nbParticipants)
	for i := 0; i < nbParticipants; i++ {
		sec, pub := genPair()
		partPubs[i] = pub
		partSec[i] = sec
	}
	dkgs = dkgGen(partPubs, partSec)
	return
}

func TestDKGNewDistKeyGenerator(t *testing.T) {
	partPubs, partSec, _ := generate()

	long := partSec[0]
	dkg, err := NewDistKeyGenerator(suite, long, partPubs, nbParticipants/2+1)
	require.Nil(t, err)
	require.NotNil(t, dkg.dealer)
	require.True(t, dkg.canIssue)
	require.True(t, dkg.canReceive)
	require.True(t, dkg.newPresent)
	// because we set old = new
	require.True(t, dkg.oldPresent)
	require.True(t, dkg.canReceive)
	require.False(t, dkg.isResharing)

	sec, _ := genPair()
	_, err = NewDistKeyGenerator(suite, sec, partPubs, nbParticipants/2+1)
	require.Error(t, err)
}

func TestDKGDeal(t *testing.T) {
	_, _, dkgs := generate()
	dkg := dkgs[0]

	dks, err := dkg.DistKeyShare()
	require.Error(t, err)
	require.Nil(t, dks)

	deals, err := dkg.Deals()
	require.Nil(t, err)
	require.Len(t, deals, nbParticipants-1)

	for i := range deals {
		require.NotNil(t, deals[i])
		require.Equal(t, uint32(0), deals[i].Index)
	}

	v, ok := dkg.verifiers[uint32(dkg.nidx)]
	require.True(t, ok)
	require.NotNil(t, v)
}

func TestDKGProcessDeal(t *testing.T) {
	_, _, dkgs := generate()

	dkg := dkgs[0]
	deals, err := dkg.Deals()
	require.Nil(t, err)

	rec := dkgs[1]
	deal := deals[1]
	require.Equal(t, int(deal.Index), 0)
	require.Equal(t, 1, rec.nidx)

	// verifier don't find itself
	goodP := rec.c.NewNodes
	rec.c.NewNodes = make([]kyber.Point, 0)
	resp, err := rec.ProcessDeal(deal)
	require.Nil(t, resp)
	require.Error(t, err)
	rec.c.NewNodes = goodP

	// good deal
	resp, err = rec.ProcessDeal(deal)
	require.NotNil(t, resp)
	require.Equal(t, vss.StatusApproval, resp.Response.Status)
	require.Nil(t, err)
	_, ok := rec.verifiers[deal.Index]
	require.True(t, ok)
	require.Equal(t, uint32(0), resp.Index)

	// duplicate
	resp, err = rec.ProcessDeal(deal)
	require.Nil(t, resp)
	require.Error(t, err)

	// wrong index
	goodIdx := deal.Index
	deal.Index = uint32(nbParticipants + 1)
	resp, err = rec.ProcessDeal(deal)
	require.Nil(t, resp)
	require.Error(t, err)
	deal.Index = goodIdx

	// wrong deal
	goodSig := deal.Deal.Signature
	deal.Deal.Signature = randomBytes(len(deal.Deal.Signature))
	resp, err = rec.ProcessDeal(deal)
	require.Nil(t, resp)
	require.Error(t, err)
	deal.Deal.Signature = goodSig

}

func TestDKGProcessResponse(t *testing.T) {
	// first peer generates wrong deal
	// second peer processes it and returns a complaint
	// first peer process the complaint

	_, _, dkgs := generate()
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
	require.Nil(t, err)
	require.NotNil(t, resp)
	require.Equal(t, vss.StatusComplaint, resp.Response.Status)
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
	require.Nil(t, j)
	require.NotNil(t, err)
	dkg.verifiers[0] = v

	// invalid response
	goodSig := resp.Response.Signature
	resp.Response.Signature = randomBytes(len(goodSig))
	j, err = dkg.ProcessResponse(resp)
	require.Nil(t, j)
	require.Error(t, err)
	resp.Response.Signature = goodSig

	// valid complaint from our deal
	j, err = dkg.ProcessResponse(resp)
	require.NotNil(t, j)
	require.Nil(t, err)

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
	require.NotNil(t, resp)
	require.Equal(t, vss.StatusComplaint, resp12.Response.Status)
	require.Equal(t, deals2[idxRec].Index, uint32(dkg2.nidx))
	require.Equal(t, resp12.Index, uint32(dkg2.nidx))
	require.Equal(t, vss.StatusComplaint, rec.verifiers[uint32(dkg2.oidx)].Responses()[uint32(rec.nidx)].Status)

	deal21.SecShare.V = goodRnd21
	deals2, err = dkg2.Deals()
	require.Nil(t, err)

	// give it to the first peer
	// process dealer 2's deal
	r, err := dkg.ProcessDeal(deals2[0])
	require.Nil(t, err)
	require.NotNil(t, r)

	// process response from peer 1
	j, err = dkg.ProcessResponse(resp12)
	require.Nil(t, j)
	require.Nil(t, err)

	// Justification part:
	// give the complaint to the dealer
	j, err = dkg2.ProcessResponse(resp12)
	require.Nil(t, err)
	require.NotNil(t, j)

	// hack because all is local, and resp has been modified locally by dkg2's
	// dealer, the status has became "justified"
	resp12.Response.Status = vss.StatusComplaint
	err = dkg.ProcessJustification(j)
	require.Nil(t, err)

	// remove verifiers
	v = dkg.verifiers[j.Index]
	delete(dkg.verifiers, j.Index)
	err = dkg.ProcessJustification(j)
	require.Error(t, err)
	dkg.verifiers[j.Index] = v

}

func TestSetTimeout(t *testing.T) {
	_, _, dkgs := generate()

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
	_, _, dkgs := generate()
	fullExchange(t, dkgs)

	for _, dkg := range dkgs {
		require.True(t, dkg.Certified())
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
		require.Equal(t, dkg.nidx, dks.Share.I)

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
		require.True(t, checkDks(dks, dkss[0]), "dist key share not equal %d vs %d", dks.Share.I, 0)
		shares[i] = dks.Share
	}

	secret, err := share.RecoverSecret(suite, shares, nbParticipants, nbParticipants)
	require.Nil(t, err)

	secretCoeffs := poly.Coefficients()
	require.Equal(t, secret.String(), secretCoeffs[0].String())

	commitSecret := suite.Point().Mul(secret, nil)
	require.Equal(t, dkss[0].Public().String(), commitSecret.String())
}

func dkgGen(partPubs []kyber.Point, partSec []kyber.Scalar) []*DistKeyGenerator {
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
	for idx, dkg := range dkgs {
		deals, err := dkg.Deals()
		require.Nil(t, err)
		for i, d := range deals {
			require.True(t, i != idx)
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
	partPubs, partSec, dkgs := generate()
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

// Test resharing to a different set of nodes with one common
func TestDKGResharingNewNodes(t *testing.T) {
	partPubs, partSec, dkgs := generate()
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
	privates[0] = dkgs[oldN-1].long
	publics[0] = suite.Point().Mul(privates[0], nil)
	for i := 1; i < newN; i++ {
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
		if i == oldN-1 {
			require.True(t, oldDkgs[i].canReceive)
			require.True(t, oldDkgs[i].canIssue)
			require.True(t, oldDkgs[i].isResharing)
			require.True(t, oldDkgs[i].newPresent)
			require.Equal(t, oldDkgs[i].oidx, i)
			require.Equal(t, 0, oldDkgs[i].nidx)
			continue
		}
		require.False(t, oldDkgs[i].canReceive)
		require.True(t, oldDkgs[i].canIssue)
		require.True(t, oldDkgs[i].isResharing)
		require.False(t, oldDkgs[i].newPresent)
		require.Equal(t, oldDkgs[i].oidx, i)
	}
	// the first one is the last old one
	newDkgs[0] = oldDkgs[oldN-1]
	for i := 1; i < newN; i++ {
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
	deals := make([]map[int]*Deal, 0, newN*newN)
	for _, dkg := range oldDkgs {
		localDeals, err := dkg.Deals()
		require.Nil(t, err)
		deals = append(deals, localDeals)
		if dkg.canReceive && dkg.nidx == 0 {
			// because it stores its own deal / response
			require.Equal(t, 1, len(dkg.verifiers))
		} else {
			require.Equal(t, 0, len(dkg.verifiers))
		}
	}

	// the index key indicates the dealer index for which the responses are for
	resps := make(map[int][]*Response)
	for i, localDeals := range deals {
		for j, d := range localDeals {
			dkg := newDkgs[j]
			resp, err := dkg.ProcessDeal(d)
			require.Nil(t, err)
			require.Equal(t, vss.StatusApproval, resp.Response.Status)
			resps[i] = append(resps[i], resp)
		}
	}

	// all new dkgs should have the same length of verifiers map
	for _, dkg := range newDkgs {
		// one deal per old participants
		require.Equal(t, oldN, len(dkg.verifiers), "dkg nidx %d failing", dkg.nidx)
	}

	// 2. Broadcast responses
	for _, dealResponses := range resps {
		for _, resp := range dealResponses {
			for _, dkg := range oldDkgs {
				// Ignore messages from ourselves
				if resp.Response.Index == uint32(dkg.nidx) {
					continue
				}
				j, err := dkg.ProcessResponse(resp)
				//fmt.Printf("old dkg %d process responses from new dkg %d about deal %d\n", dkg.oidx, dkg.nidx, resp.Index)
				if err != nil {
					fmt.Printf("old dkg at (oidx %d, nidx %d) has received response from idx %d for dealer idx %d\n", dkg.oidx, dkg.nidx, resp.Response.Index, resp.Index)
				}
				require.Nil(t, err)
				require.Nil(t, j)
			}

			for _, dkg := range newDkgs[1:] {
				// Ignore messages from ourselves
				if resp.Response.Index == uint32(dkg.nidx) {
					continue
				}
				j, err := dkg.ProcessResponse(resp)
				//fmt.Printf("new dkg %d process responses from new dkg %d about deal %d\n", dkg.nidx, dkg.nidx, resp.Index)
				if err != nil {
					fmt.Printf("new dkg at nidx %d has received response from idx %d for deal %d\n", dkg.nidx, resp.Response.Index, resp.Index)
				}
				require.Nil(t, err)
				require.Nil(t, j)
			}

		}
	}

	for _, dkg := range newDkgs {
		for i := 0; i < oldN; i++ {
			require.True(t, dkg.verifiers[uint32(i)].DealCertified(), "new dkg %d has not certified deal %d => %v", dkg.nidx, i, dkg.verifiers[uint32(i)].Responses())
		}
	}

	// 3. make sure everyone has the same QUAL set
	for _, dkg := range newDkgs {
		for _, dkg2 := range oldDkgs {
			require.True(t, dkg.isInQUAL(uint32(dkg2.oidx)), "new dkg %d has not in qual old dkg %d (qual = %v)", dkg.nidx, dkg2.oidx, dkg.QUAL())
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

func TestDKGResharingPartialNewNodes(t *testing.T) {
	partPubs, partSec, dkgs := generate()
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
	total := oldN + 2
	newOffset := oldN - 1 // idx at which a new key is added to the group

	privates := make([]kyber.Scalar, 0, newN)
	publics := make([]kyber.Point, 0, newN)
	for _, dkg := range dkgs[1:] {
		privates = append(privates, dkg.long)
		publics = append(publics, suite.Point().Mul(privates[len(privates)-1], nil))
	}
	// add two new guys
	privates = append(privates, suite.Scalar().Pick(suite.RandomStream()))
	publics = append(publics, suite.Point().Mul(privates[len(privates)-1], nil))
	privates = append(privates, suite.Scalar().Pick(suite.RandomStream()))
	publics = append(publics, suite.Point().Mul(privates[len(privates)-1], nil))

	// creating all dkgs
	totalDkgs := make([]*DistKeyGenerator, total)
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
		totalDkgs[i], err = NewDistKeyHandler(c)
		require.NoError(t, err)
		if i >= 1 {
			require.True(t, totalDkgs[i].canReceive)
			require.True(t, totalDkgs[i].canIssue)
			require.True(t, totalDkgs[i].isResharing)
			require.True(t, totalDkgs[i].newPresent)
			require.Equal(t, totalDkgs[i].oidx, i)
			require.Equal(t, i-1, totalDkgs[i].nidx)
			continue
		}
		require.False(t, totalDkgs[i].canReceive)
		require.True(t, totalDkgs[i].canIssue)
		require.True(t, totalDkgs[i].isResharing)
		require.False(t, totalDkgs[i].newPresent)
		require.Equal(t, totalDkgs[i].oidx, i)
	}
	// the first one is the last old one
	for i := oldN; i < total; i++ {
		newIdx := i - oldN + newOffset
		c := &Config{
			Suite:        suite,
			Longterm:     privates[newIdx],
			OldNodes:     partPubs,
			NewNodes:     publics,
			PublicCoeffs: shares[0].Commits,
			Threshold:    newT,
		}
		totalDkgs[i], err = NewDistKeyHandler(c)
		require.NoError(t, err)
		require.True(t, totalDkgs[i].canReceive)
		require.False(t, totalDkgs[i].canIssue)
		require.True(t, totalDkgs[i].isResharing)
		require.True(t, totalDkgs[i].newPresent)
		require.Equal(t, totalDkgs[i].nidx, newIdx)
	}
	newDkgs := totalDkgs[1:]
	oldDkgs := totalDkgs[:oldN]
	require.Equal(t, oldN, len(oldDkgs))
	require.Equal(t, newN, len(newDkgs))

	// full secret sharing exchange
	// 1. broadcast deals
	deals := make([]map[int]*Deal, 0, newN*newN)
	for _, dkg := range oldDkgs {
		localDeals, err := dkg.Deals()
		require.Nil(t, err)
		deals = append(deals, localDeals)
		if dkg.canReceive && dkg.newPresent {
			// because it stores its own deal / response
			require.Equal(t, 1, len(dkg.verifiers))
		} else {
			require.Equal(t, 0, len(dkg.verifiers))
		}
	}

	// the index key indicates the dealer index for which the responses are for
	resps := make(map[int][]*Response)
	for i, localDeals := range deals {
		for j, d := range localDeals {
			dkg := newDkgs[j]
			resp, err := dkg.ProcessDeal(d)
			require.Nil(t, err)
			require.Equal(t, vss.StatusApproval, resp.Response.Status)
			resps[i] = append(resps[i], resp)
			if i == 0 {
				//fmt.Printf("dealer (oidx %d, nidx %d) processing deal to %d from %d\n", newDkgs[i].oidx, newDkgs[i].nidx, i, d.Index)
			}
		}
	}

	// all new dkgs should have the same length of verifiers map
	for _, dkg := range newDkgs {
		// one deal per old participants
		require.Equal(t, oldN, len(dkg.verifiers), "dkg nidx %d failing", dkg.nidx)
	}

	// 2. Broadcast responses
	for _, dealResponses := range resps {
		for _, resp := range dealResponses {
			for _, dkg := range totalDkgs {
				// Ignore messages from ourselves
				if dkg.canReceive && resp.Response.Index == uint32(dkg.nidx) {
					continue
				}
				j, err := dkg.ProcessResponse(resp)
				//fmt.Printf("old dkg %d process responses from new dkg %d about deal %d\n", dkg.oidx, dkg.nidx, resp.Index)
				if err != nil {
					fmt.Printf("old dkg at (oidx %d, nidx %d) has received response from idx %d for dealer idx %d\n", dkg.oidx, dkg.nidx, resp.Response.Index, resp.Index)
				}
				require.Nil(t, err)
				require.Nil(t, j)
			}
		}
	}
	for _, dkg := range newDkgs {
		for i := 0; i < oldN; i++ {
			require.True(t, dkg.verifiers[uint32(i)].DealCertified(), "new dkg %d has not certified deal %d => %v", dkg.nidx, i, dkg.verifiers[uint32(i)].Responses())
		}
	}

	// 3. make sure everyone has the same QUAL set
	for _, dkg := range newDkgs {
		for _, dkg2 := range oldDkgs {
			require.True(t, dkg.isInQUAL(uint32(dkg2.oidx)), "new dkg %d has not in qual old dkg %d (qual = %v)", dkg.nidx, dkg2.oidx, dkg.QUAL())
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
