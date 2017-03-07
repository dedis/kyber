package vss

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
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
	fullExchange(t)

	var scs []*SecretCommits
	for _, dkg := range dkgs {
		sc, err := dkg.SecretCommits()
		require.Nil(t, err)
		scs = append(scs, sc)
	}

	for _, sc := range scs {
		for _, dkg := range dkgs {
			cc, err := dkg.ProcessSecretCommits(sc)
			assert.Nil(t, err)
			assert.Nil(t, cc)
		}
	}

	// change the sc for the second one
	wrongSc := &SecretCommits{}
	wrongSc.Index = scs[0].Index
	wrongSc.SessionID = scs[0].SessionID
	wrongSc.Commitments = make([]abstract.Point, len(scs[0].Commitments))
	copy(wrongSc.Commitments, scs[0].Commitments)
	//goodScCommit := scs[0].Commitments[0]
	wrongSc.Commitments[0] = suite.Point().Null()
	msg := msgSecretCommit(wrongSc)
	wrongSc.Signature, _ = sign.Schnorr(suite, dkgs[0].long, msg)

	dkg := dkgs[1]
	cc, err := dkg.ProcessSecretCommits(wrongSc)
	assert.Nil(t, err)
	assert.NotNil(t, cc)

	dkg2 := dkgs[2]
	// ComplaintCommits: wrong index
	goodIndex := cc.Index
	cc.Index = uint32(nbParticipants)
	rc, err := dkg2.ProcessComplaintCommits(cc)
	assert.Nil(t, rc)
	assert.Error(t, err)
	cc.Index = goodIndex

	// invalid signature
	goodSig := cc.Signature
	cc.Signature = randomBytes(len(cc.Signature))
	rc, err = dkg2.ProcessComplaintCommits(cc)
	assert.Nil(t, rc)
	assert.Error(t, err)
	cc.Signature = goodSig

	// no verifiers
	v := dkg2.verifiers[uint32(0)]
	delete(dkg2.verifiers, uint32(0))
	rc, err = dkg2.ProcessComplaintCommits(cc)
	assert.Nil(t, rc)
	assert.Error(t, err)
	dkg2.verifiers[uint32(0)] = v

	// deal does not verify
	goodDeal := cc.Deal
	cc.Deal = &vss.Deal{
		SessionID:   goodDeal.SessionID,
		SecShare:    goodDeal.SecShare,
		RndShare:    goodDeal.RndShare,
		T:           goodDeal.T,
		Commitments: goodDeal.Commitments,
		Signature:   randomBytes(len(goodDeal.Signature)),
	}
	rc, err = dkg2.ProcessComplaintCommits(cc)
	assert.Nil(t, rc)
	assert.Error(t, err)
	cc.Deal = goodDeal

	//  no commitments
	sc := dkg2.commitments[uint32(0)]
	delete(dkg2.commitments, uint32(0))
	rc, err = dkg2.ProcessComplaintCommits(cc)
	assert.Nil(t, rc)
	assert.Error(t, err)
	dkg2.commitments[uint32(0)] = sc

	// secret commits are passing the check
	rc, err = dkg2.ProcessComplaintCommits(cc)
	assert.Nil(t, rc)
	assert.Error(t, err)

	// TODO find a way to be the malicious guys,i.e.
	// make a deal which validates, but revealing the commitments coefficients makes
	// the check fails.
	// f is the secret polynomial
	// g is the "random" one
	// [f(i) + g(i)]*G == [F + G](i)
	// but
	// f(i)*G != F(i)
	/*goodV := cc.Deal.SecShare.V*/
	//goodDSig := cc.Deal.Signature
	//cc.Deal.SecShare.V = suite.Scalar().Zero()
	//msg = msgDeal(cc.Deal)
	//sig, _ := sign.Schnorr(suite, dkgs[cc.DealerIndex].long, msg)
	//cc.Deal.Signature = sig
	//msg = msgCommitComplaint(cc)
	//sig, _ = sign.Schnorr(suite, dkgs[cc.Index].long, msg)
	//goodCCSig := cc.Signature
	//cc.Signature = sig
	//rc, err = dkg2.ProcessComplaintCommits(cc)
	//assert.Nil(t, err)
	//assert.NotNil(t, rc)
	//cc.Deal.SecShare.V = goodV
	//cc.Deal.Signature = goodDSig
	//cc.Signature = goodCCSig

}

func TestDKGReconstructCommits(t *testing.T) {
	fullExchange(t)

	var scs []*SecretCommits
	for _, dkg := range dkgs {
		sc, err := dkg.SecretCommits()
		require.Nil(t, err)
		scs = append(scs, sc)
	}

	// give the secret commits to all dkgs but the second one
	for _, sc := range scs {
		for _, dkg := range dkgs[2:] {
			cc, err := dkg.ProcessSecretCommits(sc)
			assert.Nil(t, err)
			assert.Nil(t, cc)
		}
	}

	// peer 1 wants to reconstruct coeffs from dealer 1
	rc := &ReconstructCommits{
		Index:       1,
		DealerIndex: 0,
		Share:       dkgs[uint32(1)].verifiers[uint32(0)].Deal().SecShare,
	}
	msg := msgReconstructCommits(rc)
	rc.Signature, _ = sign.Schnorr(suite, dkgs[1].long, msg)

	dkg2 := dkgs[2]
	// reconstructed already set
	dkg2.reconstructed[0] = true
	assert.Nil(t, dkg2.ProcessReconstructCommits(rc))
	delete(dkg2.reconstructed, uint32(0))

	// commitments not invalidated by any complaints
	assert.Error(t, dkg2.ProcessReconstructCommits(rc))
	//comms := dkg2.commitments[uint32(0)]
	delete(dkg2.commitments, uint32(0))

	// invalid index
	goodI := rc.Index
	rc.Index = uint32(nbParticipants)
	assert.Error(t, dkg2.ProcessReconstructCommits(rc))
	rc.Index = goodI

	// invalid sig
	goodSig := rc.Signature
	rc.Signature = randomBytes(len(goodSig))
	assert.Error(t, dkg2.ProcessReconstructCommits(rc))
	rc.Signature = goodSig

	// all fine
	assert.Nil(t, dkg2.ProcessReconstructCommits(rc))

	// packet already received
	var found bool
	for _, p := range dkg2.pendingReconstruct[rc.DealerIndex] {
		if p.Index == rc.Index {
			found = true
			break
		}
	}
	assert.True(t, found)
	assert.False(t, dkg2.Finished())
	// generate enough secret commits  to recover the secret
	for _, dkg := range dkgs[1:] {
		rc = &ReconstructCommits{
			Index:       dkg.index,
			DealerIndex: 0,
			Share:       dkg.verifiers[uint32(0)].Deal().SecShare,
		}
		msg := msgReconstructCommits(rc)
		rc.Signature, _ = sign.Schnorr(suite, dkg.long, msg)
		dkg2.ProcessReconstructCommits(rc)
	}
	assert.True(t, dkg2.reconstructed[uint32(0)])
	com := dkg2.commitments[uint32(0)]
	assert.NotNil(t, com)
	assert.Equal(t, dkgs[0].dealer.SecretCommit().String(), com.Commit().String())

	assert.True(t, dkg2.Finished())
}

// Copy from vss.go... TODO: look to a nice separation with vss, using a
// internal/ package might be the solution so it does not export methods just
// for testing.
func msgDeal(d *vss.Deal) []byte {
	var buf bytes.Buffer
	buf.WriteString("deal")
	buf.Write(d.SessionID) // sid already includes all other info
	binary.Write(&buf, binary.LittleEndian, d.SecShare.I)
	d.SecShare.V.MarshalTo(&buf)
	binary.Write(&buf, binary.LittleEndian, d.RndShare.I)
	d.RndShare.V.MarshalTo(&buf)
	return buf.Bytes()
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

	// check that we can't get the dist key share before exchanging commitments
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

	// everyone should be finished
	for _, dkg := range dkgs {
		assert.True(t, dkg.Finished())
	}
	// verify integrity of shares etc
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
		assert.True(t, checkDks(dks, dkss[0]), "dist key share not equal %d vs %d", dks.Share.I, 0)
		shares[i] = dks.Share
	}

	secret, err := share.RecoverSecret(suite, shares, nbParticipants, nbParticipants)
	assert.Nil(t, err)

	commitSecret := suite.Point().Mul(nil, secret)
	assert.Equal(t, dkss[0].Public().String(), commitSecret.String())
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
