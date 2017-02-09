package vss

import (
	"crypto/rand"
	"testing"

	"github.com/dedis/crypto/abstract"
	"github.com/dedis/crypto/ed25519"
	"github.com/dedis/crypto/random"
	"github.com/dedis/crypto/share"
	"github.com/dedis/crypto/share/vss"
	"github.com/dedis/crypto/sign"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var suite = ed25519.NewAES128SHA256Ed25519(false)

var nbParticipants = 7

var partPubs []abstract.Point
var partSec []abstract.Scalar

var dkgs []*DistKeyGenerator

func dkgGen() []*DistKeyGenerator {
	dkgs := make([]*DistKeyGenerator, nbParticipants)
	for i := 0; i < nbParticipants; i++ {
		dkg, err := NewDistKeyGenerator(suite, partSec[i], partPubs, random.Stream, nbParticipants/2+1)
		if err != nil {
			panic(err)
		}
		dkgs[i] = dkg
	}
	return dkgs
}

func genPair() (abstract.Scalar, abstract.Point) {
	sc := suite.Scalar().Pick(random.Stream)
	return sc, suite.Point().Mul(nil, sc)
}

func randomBytes(n int) []byte {
	var buff = make([]byte, n)
	rand.Read(buff[:])
	return buff
}

func init() {
	partPubs = make([]abstract.Point, nbParticipants)
	partSec = make([]abstract.Scalar, nbParticipants)
	for i := 0; i < nbParticipants; i++ {
		sec, pub := genPair()
		partPubs[i] = pub
		partSec[i] = sec
	}
	dkgs = dkgGen()
}

func TestDKGNewDistKeyGenerator(t *testing.T) {
	long := partSec[0]
	dkg, err := NewDistKeyGenerator(suite, long, partPubs, random.Stream, nbParticipants/2+1)
	assert.Nil(t, err)
	assert.NotNil(t, dkg.dealer)

	sec, _ := genPair()
	_, err = NewDistKeyGenerator(suite, sec, partPubs, random.Stream, nbParticipants/2+1)
	assert.Error(t, err)

}

func TestDKGDeal(t *testing.T) {
	dkg := dkgs[0]

	deals := dkg.Deals()
	assert.Len(t, deals, nbParticipants-1)

	for i := range deals {
		assert.NotNil(t, deals[i])
		assert.Equal(t, uint32(0), deals[i].Index)
	}

	v, ok := dkg.verifiers[dkg.index]
	assert.True(t, ok)
	assert.NotNil(t, v)
}

func TestDKGProcessDeal(t *testing.T) {
	dkgs = dkgGen()
	dkg := dkgs[0]
	deals := dkg.Deals()

	rec := dkgs[1]
	deal := deals[1]
	assert.Equal(t, int(deal.Index), 0)
	assert.Equal(t, uint32(1), rec.index)

	// good deal
	resp, err := rec.ProcessDeal(deal)
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
	wrongSig := randomBytes(len(deal.Deal.Signature))
	goodSig := deal.Deal.Signature
	deal.Deal.Signature = wrongSig
	resp, err = rec.ProcessDeal(deal)
	assert.Nil(t, resp)
	assert.Error(t, err)
	deal.Deal.SessionID = goodSig
}

func TestDKGProcessResponse(t *testing.T) {
	dkgs = dkgGen()
	dkg := dkgs[0]
	deals := dkg.Deals()
	v, ok := dkg.verifiers[0]
	require.NotNil(t, v)
	require.True(t, ok)

	rec := dkgs[1]
	deal := deals[1]
	sig := deal.Deal.Signature
	deal.Deal.Signature = randomBytes(len(sig))

	// give a wrong deal
	resp, err := rec.ProcessDeal(deal)
	assert.NotNil(t, resp)
	assert.Equal(t, vss.StatusComplaint, resp.Response.Status)
	assert.Nil(t, err)
	deal.Deal.Signature = sig

	// no verifier tied to Response
	v = dkg.verifiers[0]
	require.NotNil(t, v)
	delete(dkg.verifiers, 0)
	j, err := dkg.ProcessResponse(resp)
	assert.Nil(t, j)
	assert.NotNil(t, err)
	dkg.verifiers[resp.Index] = v

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
	deals2 := dkg2.Deals()
	// fake a wrong deal
	deal21 := deals2[1]
	deal20 := deals2[0]
	sig21 := deal21.Deal.Signature
	deal21.Deal.Signature = randomBytes(32)

	resp, err = rec.ProcessDeal(deal21)
	assert.NotNil(t, resp)
	assert.Equal(t, vss.StatusComplaint, resp.Response.Status)
	deal21.Deal.Signature = sig21

	// give it to the first peer
	// XXX Should we let peers know about approval/complaint for non-received
	// deal yet ?
	// process dealer 2's deal
	dkg.ProcessDeal(deal20)
	// process response from peer 1
	j, err = dkg.ProcessResponse(resp)
	assert.Nil(t, j)
	assert.Nil(t, err)

	// Justification part:
	// give the complaint to the dealer
	j, err = dkg2.ProcessResponse(resp)
	assert.Nil(t, err)
	assert.NotNil(t, j)

	// hack because all is local, and resp has been modified locally by dkg2's
	// verifier
	resp.Response.Status = vss.StatusComplaint
	err = dkg.ProcessJustification(j)
	assert.Nil(t, err)

	// remove verifiers
	v = dkg.verifiers[j.Index]
	delete(dkg.verifiers, j.Index)
	err = dkg.ProcessJustification(j)
	assert.Error(t, err)
	dkg.verifiers[j.Index] = v
}

func TestDKGSecretCommits(t *testing.T) {
	fullExchange(t)

	dkg := dkgs[0]

	sc, err := dkg.SecretCommits()
	assert.Nil(t, err)
	msg := msgSecretCommit(sc)
	assert.Nil(t, sign.VerifySchnorr(suite, dkg.pub, msg, sc.Signature))

	dkg2 := dkgs[1]
	// wrong index
	goodIdx := sc.Index
	sc.Index = uint32(nbParticipants + 1)
	cc, err := dkg2.ProcessSecretCommits(sc)
	assert.Nil(t, cc)
	assert.Error(t, err)
	sc.Index = goodIdx
	// not in qual XXX how to test...

	// invalid sig
	goodSig := sc.Signature
	sc.Signature = randomBytes(len(goodSig))
	cc, err = dkg2.ProcessSecretCommits(sc)
	assert.Nil(t, cc)
	assert.Error(t, err)
	sc.Signature = goodSig
	// invalid session id
	goodSid := sc.SessionID
	sc.SessionID = randomBytes(len(goodSid))
	cc, err = dkg2.ProcessSecretCommits(sc)
	assert.Nil(t, cc)
	assert.Error(t, err)
	sc.SessionID = goodSid

	// wrong commitments
	goodPoint := sc.Commitments[0]
	sc.Commitments[0] = suite.Point().Null()
	msg = msgSecretCommit(sc)
	sig, err := sign.Schnorr(suite, dkg.long, msg)
	require.Nil(t, err)
	goodSig = sc.Signature
	sc.Signature = sig
	cc, err = dkg2.ProcessSecretCommits(sc)
	assert.NotNil(t, cc)
	assert.Nil(t, err)
	sc.Commitments[0] = goodPoint
	sc.Signature = goodSig

	// all fine
	cc, err = dkg2.ProcessSecretCommits(sc)
	assert.Nil(t, cc)
	assert.Nil(t, err)
}

func TestDKGComplaintCommits(t *testing.T) {
	/* //  --- process the complaint ---*/
	//// invalid index
	//ccGoodIndex := cc.Index
	//cc.Index = uint32(nbParticipants + 1)
	//d, err := dkg.ProcessCommitComplaint(cc)
	//assert.Nil(t, d)
	//assert.Error(t, err)
	//cc.Index = ccGoodIndex

	//// invalid signature
	//ccGoodSig := cc.Signature
	//cc.Signature = randomBytes(len(cc.Signature))
	//d, err = dkg.ProcessCommitComplaint(cc)
	//assert.Nil(t, d)
	//assert.Error(t, err)
	//cc.Signature = ccGoodSig

	//// wrong DealerIndex
	//ccGoodDealerIndex := cc.DealerIndex
	//cc.DealerIndex = uint32(nbParticipants + 1)
	//d, err = dkg.ProcessCommitComplaint(cc)
	//assert.Error(t, err)
	//assert.Nil(t, d)
	//cc.DealerIndex = ccGoodDealerIndex

	//// wrong deal
	//ccDealSID := cc.Deal.SessionID
	//cc.Deal.SessionID = randomBytes(len(ccDealSID))
	//d, err = dkg.ProcessCommitComplaint(cc)
	//assert.Error(t, err)
	//assert.Nil(t, d)
	//cc.Deal.SessionID = ccDealSID

	//// XXX Skip non-received commitments for now

	//// correct verification of the secshare (commits are good at this point)
	//sc2, err := dkg2.SecretCommits()
	//assert.Nil(t, err)
	//cc2, err := dkg.ProcessSecretCommits(sc2)
	//assert.Nil(t, err)
	//assert.Nil(t, cc)
	//// here
	//d, err = dkg.ProcessCommitComplaint(cc2)
	//assert.Nil(t, d)
	//assert.Error(t, err)

	//// normal behavior
	//polycommits2 := dkg.commitments[dkg2.index]
	//_, commits2 := polycommits2.Info()
	//commits20 := commits2[0]
	//commits2[0] = suite.Point().Null()
	//d, err = dkg.ProcessCommitComplaint(cc)
	//assert.Nil(t, err)
	//assert.NotNil(t, d)
	//commits2[0] = commits20

	// ----- process the complaint END ----

}

func TestDistKeyShare(t *testing.T) {
	fullExchange(t)

	var scs []*SecretCommits
	for i, dkg := range dkgs[:len(dkgs)-1] {
		sc, err := dkg.SecretCommits()
		require.Nil(t, err)
		scs = append(scs, sc)
		for j, dkg := range dkgs[:len(dkgs)-1] {
			if i == j {
				continue
			}
			cc, err := dkg.ProcessSecretCommits(sc)
			require.Nil(t, err)
			require.Nil(t, cc)
		}
	}

	lastDkg := dkgs[len(dkgs)-1]
	dks, err := lastDkg.DistKeyShare()
	assert.Nil(t, dks)
	assert.Error(t, err)

	for _, sc := range scs {
		cc, err := lastDkg.ProcessSecretCommits(sc)
		require.Nil(t, cc)
		require.Nil(t, err)
	}

	sc, err := lastDkg.SecretCommits()
	require.Nil(t, err)
	require.NotNil(t, sc)

	for _, dkg := range dkgs[:len(dkgs)-1] {
		sc, err := dkg.ProcessSecretCommits(sc)
		require.Nil(t, sc)
		require.Nil(t, err)

		require.Equal(t, nbParticipants, len(dkg.QUAL()))
		require.Equal(t, nbParticipants, len(dkg.commitments))
	}

	// missing one commitment
	lastCommitment0 := lastDkg.commitments[0]
	delete(lastDkg.commitments, uint32(0))
	dks, err = lastDkg.DistKeyShare()
	assert.Nil(t, dks)
	assert.Error(t, err)
	lastDkg.commitments[uint32(0)] = lastCommitment0

	// everyone should be certified

	// normal
	dkss := make([]*DistKeyShare, nbParticipants)
	for i, dkg := range dkgs {
		dks, err := dkg.DistKeyShare()
		require.NotNil(t, dks)
		assert.Nil(t, err)
		dkss[i] = dks
		assert.Equal(t, dkg.index, uint32(dks.Share.I))
	}

	shares := make([]*share.PriShare, nbParticipants)
	for i, dks := range dkss {
		if !dks.Public.Equal(dkss[0].Public) {
			t.Errorf("dist key share not equal %d vs %d", dks.Share.I, 0)
		}
		shares[i] = dks.Share
	}

	secret, err := share.RecoverSecret(suite, shares, nbParticipants, nbParticipants)
	assert.Nil(t, err)

	commitSecret := suite.Point().Mul(nil, secret)
	assert.Equal(t, dkss[0].Public.String(), commitSecret.String())
}

func fullExchange(t *testing.T) {
	dkgs = dkgGen()
	// full secret sharing exchange
	// 1. broadcast deals
	resps := make([]*Response, 0, nbParticipants*nbParticipants)
	for _, dkg := range dkgs {
		deals := dkg.Deals()
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
			// ignore all messages from ourself
			if resp.Response.Index == dkg.index {
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
			require.True(t, dkg.isInQUAL(dkg2.index))
		}
	}

}
