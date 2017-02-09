package vss

import (
	"math/rand"
	"testing"

	"github.com/dedis/crypto/abstract"
	"github.com/dedis/crypto/ed25519"
	"github.com/dedis/crypto/random"
	"github.com/dedis/crypto/sign"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var suite = ed25519.NewAES128SHA256Ed25519(false)

var reader = random.Stream

var nbVerifiers = 7

var vssThreshold int

var verifiersPub []abstract.Point
var verifiersSec []abstract.Scalar

var dealerPub abstract.Point
var dealerSec abstract.Scalar

var secret abstract.Scalar

func genPair() (abstract.Scalar, abstract.Point) {
	secret := suite.Scalar().Pick(reader)
	public := suite.Point().Mul(nil, secret)
	return secret, public
}

func genCommits(n int) ([]abstract.Scalar, []abstract.Point) {
	var secrets = make([]abstract.Scalar, n)
	var publics = make([]abstract.Point, n)
	for i := 0; i < n; i++ {
		secrets[i], publics[i] = genPair()
	}
	return secrets, publics
}

func genDealer() *Dealer {
	d, _ := NewDealer(suite, dealerSec, secret, verifiersPub, reader, vssThreshold)
	return d
}

func genAll() (*Dealer, []*Verifier) {
	dealer := genDealer()
	var verifiers = make([]*Verifier, nbVerifiers)
	for i := 0; i < nbVerifiers; i++ {
		v, _ := NewVerifier(suite, verifiersSec[i], dealerPub, verifiersPub)
		verifiers[i] = v
	}
	return dealer, verifiers
}

func randomBytes(n int) []byte {
	var buff = make([]byte, n)
	_, err := rand.Read(buff)
	if err != nil {
		panic(err)
	}
	return buff
}

func init() {
	verifiersSec, verifiersPub = genCommits(nbVerifiers)
	dealerSec, dealerPub = genPair()
	secret, _ = genPair()
	vssThreshold = MinimumT(nbVerifiers)
}

func TestVSSWhole(t *testing.T) {
	dealer, verifiers := genAll()
	// 1. dispatch deal
	resps := make([]*Response, nbVerifiers)
	for i, d := range dealer.Deals() {
		resp, err := verifiers[i].ProcessDeal(d)
		require.Nil(t, err)
		resps[i] = resp
	}

	// 2. dispatch responses
	for _, resp := range resps {
		for i, v := range verifiers {
			if resp.Index == uint32(i) {
				continue
			}
			require.Nil(t, v.ProcessResponse(resp))
		}
		// 2.1. check dealer (no justification here)
		j, err := dealer.ProcessResponse(resp)
		require.Nil(t, err)
		require.Nil(t, j)
	}

	// 3. check certified
	for _, v := range verifiers {
		require.True(t, v.DealCertified())
	}

	// 4. collect deals
	deals := make([]*Deal, nbVerifiers)
	for i, v := range verifiers {
		deals[i] = v.Deal()
	}

	// 5. recover
	sec, err := RecoverSecret(suite, deals, nbVerifiers, MinimumT(nbVerifiers))
	assert.Nil(t, err)
	require.NotNil(t, sec)
	assert.Equal(t, dealer.secret.String(), sec.String())
}

func TestVSSDealerNew(t *testing.T) {
	goodT := MinimumT(nbVerifiers)
	_, err := NewDealer(suite, dealerSec, secret, verifiersPub, reader, goodT)
	assert.NoError(t, err)

	for _, badT := range []int{0, 1, -4} {
		_, err = NewDealer(suite, dealerSec, secret, verifiersPub, reader, badT)
		assert.Error(t, err)
	}
}

func TestVSSVerifierNew(t *testing.T) {
	randIdx := rand.Int() % len(verifiersPub)
	v, err := NewVerifier(suite, verifiersSec[randIdx], dealerPub, verifiersPub)
	assert.NoError(t, err)
	assert.Equal(t, randIdx, v.index)

	wrongKey := suite.Scalar().Pick(reader)
	_, err = NewVerifier(suite, wrongKey, dealerPub, verifiersPub)
	assert.Error(t, err)
}

func TestVSSShare(t *testing.T) {
	dealer, verifiers := genAll()
	ver := verifiers[0]
	resp, err := ver.ProcessDeal(dealer.deals[0])
	require.NotNil(t, resp)
	require.Equal(t, StatusApproval, resp.Status)
	require.Nil(t, err)

	aggr := ver.aggregator

	for i := 1; i < aggr.t-1; i++ {
		aggr.responses[uint32(i)] = &Response{Status: StatusApproval}
	}
	// not enough approvals
	assert.Nil(t, ver.Deal())
	aggr.responses[uint32(aggr.t)] = &Response{Status: StatusApproval}
	// deal not certified
	aggr.badDealer = true
	assert.Nil(t, ver.Deal())
	aggr.badDealer = false

	assert.NotNil(t, ver.Deal())

}

func TestVSSAggregatorEnoughApprovals(t *testing.T) {
	dealer := genDealer()
	aggr := dealer.aggregator
	// just below
	for i := 0; i < aggr.t-1; i++ {
		aggr.responses[uint32(i)] = &Response{Status: StatusApproval}
	}
	assert.False(t, aggr.EnoughApprovals())
	assert.Nil(t, dealer.SecretCommit())

	aggr.responses[uint32(aggr.t)] = &Response{Status: StatusApproval}
	assert.True(t, aggr.EnoughApprovals())

	for i := aggr.t + 1; i < nbVerifiers; i++ {
		aggr.responses[uint32(i)] = &Response{Status: StatusApproval}
	}
	assert.True(t, aggr.EnoughApprovals())
	assert.Equal(t, suite.Point().Mul(nil, secret), dealer.SecretCommit())
}

func TestVSSAggregatorDealCertified(t *testing.T) {
	dealer := genDealer()
	aggr := dealer.aggregator

	for i := 0; i < aggr.t; i++ {
		aggr.responses[uint32(i)] = &Response{Status: StatusApproval}
	}
	assert.True(t, aggr.DealCertified())
	assert.Equal(t, suite.Point().Mul(nil, secret), dealer.SecretCommit())
	// bad dealer response
	aggr.badDealer = true
	assert.False(t, aggr.DealCertified())
	assert.Nil(t, dealer.SecretCommit())
	// inconsistent state on purpose
	// too much complaints
	for i := 0; i < aggr.t; i++ {
		aggr.responses[uint32(i)] = &Response{Status: StatusComplaint}
	}
	assert.False(t, aggr.DealCertified())
}

func TestVSSVerifierReceiveDeal(t *testing.T) {
	dealer, verifiers := genAll()
	v := verifiers[0]
	d := dealer.deals[0]

	// correct deal
	resp, err := v.ProcessDeal(d)
	require.NotNil(t, resp)
	assert.Equal(t, StatusApproval, resp.Status)
	assert.Nil(t, err)
	assert.Equal(t, v.index, int(resp.Index))
	assert.Equal(t, dealer.sid, resp.SessionID)
	assert.Nil(t, sign.VerifySchnorr(suite, v.pub, msgResponse(resp), resp.Signature))
	assert.Equal(t, v.responses[uint32(v.index)], resp)

	// wrong index
	goodIdx := d.SecShare.I
	d.SecShare.I = (goodIdx - 1) % nbVerifiers
	resp, err = v.ProcessDeal(d)
	assert.Error(t, err)
	assert.Nil(t, resp)
	d.SecShare.I = goodIdx

	// wrong commitments
	goodCommit := d.Commitments[0]
	d.Commitments[0], _ = suite.Point().Pick(nil, random.Stream)
	resp, err = v.ProcessDeal(d)
	assert.Error(t, err)
	assert.Nil(t, resp)
	d.Commitments[0] = goodCommit

	// already seen twice
	resp, err = v.ProcessDeal(d)
	assert.Nil(t, resp)
	assert.Error(t, err)
	v.aggregator.deal = nil

	// approval already existing from same origin, should never happen right ?
	v.aggregator.responses[uint32(v.index)] = &Response{Status: StatusApproval}
	d.Commitments[0], _ = suite.Point().Pick(nil, random.Stream)
	resp, err = v.ProcessDeal(d)
	assert.Nil(t, resp)
	assert.Error(t, err)
	d.Commitments[0] = goodCommit

	// valid complaint
	v.aggregator.deal = nil
	delete(v.aggregator.responses, uint32(v.index))
	d.RndShare.V = suite.Scalar().SetBytes(randomBytes(32))
	resp, err = v.ProcessDeal(d)
	assert.NotNil(t, resp)
	assert.Equal(t, StatusComplaint, resp.Status)
	assert.Nil(t, err)
}

func TestVSSAggregatorVerifyJustification(t *testing.T) {
	dealer, verifiers := genAll()
	v := verifiers[0]
	deals := dealer.Deals()
	d := deals[0]

	wrongV := suite.Scalar().Pick(random.Stream)
	goodV := d.SecShare.V
	d.SecShare.V = wrongV
	resp, err := v.ProcessDeal(d)
	assert.NotNil(t, resp)
	assert.Equal(t, StatusComplaint, resp.Status)
	assert.Nil(t, err)
	assert.Equal(t, v.responses[uint32(v.index)], resp)
	d.SecShare.V = goodV // in tests, pointers point to the same underlying share..

	j, err := dealer.ProcessResponse(resp)

	// invalid deal justified
	goodV = j.Deal.SecShare.V
	j.Deal.SecShare.V = wrongV
	err = v.ProcessJustification(j)
	assert.Error(t, err)
	assert.True(t, v.aggregator.badDealer)
	j.Deal.SecShare.V = goodV
	v.aggregator.badDealer = false

	// valid complaint
	assert.Nil(t, v.ProcessJustification(j))

	// invalid  complaint
	resp.SessionID = randomBytes(len(resp.SessionID))
	badJ, err := dealer.ProcessResponse(resp)
	assert.Nil(t, badJ)
	assert.Error(t, err)
	resp.SessionID = dealer.sid

	// no complaints for this justification before
	delete(v.aggregator.responses, uint32(v.index))
	assert.Error(t, v.ProcessJustification(j))
	v.aggregator.responses[uint32(v.index)] = resp

}

func TestVSSAggregatorVerifyResponseDuplicate(t *testing.T) {
	dealer, verifiers := genAll()
	v1 := verifiers[0]
	v2 := verifiers[1]
	d1 := dealer.deals[0]
	d2 := dealer.deals[1]

	resp1, err := v1.ProcessDeal(d1)
	assert.Nil(t, err)
	assert.NotNil(t, resp1)
	assert.Equal(t, StatusApproval, resp1.Status)

	resp2, err := v2.ProcessDeal(d2)
	assert.Nil(t, err)
	assert.NotNil(t, resp2)
	assert.Equal(t, StatusApproval, resp2.Status)

	err = v1.ProcessResponse(resp2)
	assert.Nil(t, err)
	r, ok := v1.aggregator.responses[uint32(v2.index)]
	assert.True(t, ok)
	assert.Equal(t, resp2, r)

	err = v1.ProcessResponse(resp2)
	assert.Error(t, err)

	delete(v1.aggregator.responses, uint32(v2.index))
	v1.aggregator.responses[uint32(v2.index)] = &Response{Status: StatusApproval}
	err = v1.ProcessResponse(resp2)
	assert.Error(t, err)
}

func TestVSSAggregatorVerifyResponse(t *testing.T) {
	dealer, verifiers := genAll()
	v := verifiers[0]
	deal := dealer.deals[0]
	//goodSec := deal.SecShare.V
	wrongSec, _ := genPair()
	deal.SecShare.V = wrongSec

	// valid complaint
	resp, err := v.ProcessDeal(deal)
	assert.Nil(t, err)
	assert.NotNil(t, resp)
	assert.Equal(t, StatusComplaint, resp.Status)
	assert.NotNil(t, v.aggregator)
	assert.Equal(t, resp.SessionID, dealer.sid)

	aggr := v.aggregator
	r, ok := aggr.responses[uint32(v.index)]
	assert.True(t, ok)
	assert.Equal(t, StatusComplaint, r.Status)

	// wrong index
	resp.Index = uint32(len(verifiersPub))
	sig, err := sign.Schnorr(suite, v.long, msgResponse(resp))
	resp.Signature = sig
	assert.Error(t, aggr.verifyResponse(resp))
	resp.Index = 0

	// wrong signature
	goodSig := resp.Signature
	resp.Signature = randomBytes(len(goodSig))
	assert.Error(t, aggr.verifyResponse(resp))
	resp.Signature = goodSig

	// wrongID
	wrongID := randomBytes(len(resp.SessionID))
	goodID := resp.SessionID
	resp.SessionID = wrongID
	assert.Error(t, aggr.verifyResponse(resp))
	resp.SessionID = goodID
}

func TestVSSAggregatorVerifyDeal(t *testing.T) {
	dealer := genDealer()
	aggr := dealer.aggregator
	deals := dealer.Deals()

	// OK
	deal := deals[0]
	err := aggr.VerifyDeal(deal, true)
	assert.NoError(t, err)
	assert.NotNil(t, aggr.deal)

	// already received deal
	err = aggr.VerifyDeal(deal, true)
	assert.Error(t, err)

	// wrong T
	wrongT := uint32(1)
	goodT := deal.T
	deal.T = wrongT
	assert.Error(t, aggr.VerifyDeal(deal, false))
	deal.T = goodT

	// wrong SessionID
	goodSid := deal.SessionID
	deal.SessionID = make([]byte, 32)
	assert.Error(t, aggr.VerifyDeal(deal, false))
	deal.SessionID = goodSid

	// index different in one share
	goodI := deal.RndShare.I
	deal.RndShare.I = goodI + 1
	assert.Error(t, aggr.VerifyDeal(deal, false))
	deal.RndShare.I = goodI

	// index not in bounds
	deal.SecShare.I = -1
	assert.Error(t, aggr.VerifyDeal(deal, false))
	deal.SecShare.I = len(verifiersPub)
	assert.Error(t, aggr.VerifyDeal(deal, false))

	// shares invalid in respect to the commitments
	wrongSec, _ := genPair()
	deal.SecShare.V = wrongSec
	assert.Error(t, aggr.VerifyDeal(deal, false))
}

func TestVSSAggregatorAddComplaint(t *testing.T) {
	dealer := genDealer()
	aggr := dealer.aggregator

	var idx uint32 = 1
	c := &Response{
		Index:  idx,
		Status: StatusComplaint,
	}
	// ok
	assert.Nil(t, aggr.addResponse(c))
	assert.Equal(t, aggr.responses[idx], c)

	// response already there
	assert.Error(t, aggr.addResponse(c))
	delete(aggr.responses, idx)

}

func TestVSSSessionID(t *testing.T) {
	dealer, _ := NewDealer(suite, dealerSec, secret, verifiersPub, reader, vssThreshold)
	commitments := dealer.deals[0].Commitments
	sid, err := sessionID(suite, dealerPub, verifiersPub, commitments, dealer.t)
	assert.NoError(t, err)

	sid2, err2 := sessionID(suite, dealerPub, verifiersPub, commitments, dealer.t)
	assert.NoError(t, err2)
	assert.Equal(t, sid, sid2)

	wrongDealerPub := suite.Point().Add(dealerPub, dealerPub)

	sid3, err3 := sessionID(suite, wrongDealerPub, verifiersPub, commitments, dealer.t)
	assert.NoError(t, err3)
	assert.NotEqual(t, sid3, sid2)
}

func TestVSSFindPub(t *testing.T) {
	p, ok := findPub(verifiersPub, 0)
	assert.True(t, ok)
	assert.Equal(t, verifiersPub[0], p)

	p, ok = findPub(verifiersPub, uint32(len(verifiersPub)))
	assert.False(t, ok)
	assert.Nil(t, p)

}
