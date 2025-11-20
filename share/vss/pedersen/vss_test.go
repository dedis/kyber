package vss

import (
	"fmt"
	"math/rand"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.dedis.ch/kyber/v4"
	"go.dedis.ch/kyber/v4/group/edwards25519"
	"go.dedis.ch/kyber/v4/share/vss"
	"go.dedis.ch/kyber/v4/sign/schnorr"
	"go.dedis.ch/kyber/v4/xof/blake2xb"
	"go.dedis.ch/protobuf"
)

var rng = blake2xb.New(nil)

var suite = edwards25519.NewBlakeSHA256Ed25519WithRand(rng)

var nbVerifiers = 7

var vssThreshold int

var verifiersPub []kyber.Point
var verifiersSec []kyber.Scalar

var dealerPub kyber.Point
var dealerSec kyber.Scalar

var secret kyber.Scalar

func init() {
	verifiersSec, verifiersPub = genCommits(nbVerifiers)
	dealerSec, dealerPub = genPair()
	secret, _ = genPair()
	vssThreshold = vss.MinimumT(nbVerifiers)
}

func TestMinimumT(t *testing.T) {
	tests := []struct {
		input  int
		output int
	}{
		{10, 6},
		{6, 4},
		{4, 3},
		{3, 2},
		{2, 2},
		{7, 4},
		{8, 5},
		{9, 5},
	}
	for _, test := range tests {
		in := test.input
		exp := test.output
		t.Run(fmt.Sprintf("VSS-MininumT-%d", test.input), func(t *testing.T) {
			if vss.MinimumT(in) != exp {
				t.Fail()
			}
		})
	}
}

func TestVSSWhole(t *testing.T) {
	dealer, verifiers := genAll()

	// 1. dispatch deal
	resps := make([]*vss.Response, nbVerifiers)
	encDeals, err := dealer.EncryptedDeals()
	require.Nil(t, err)
	for i, d := range encDeals {
		require.Equal(t, vss.ErrNoDealBeforeResponse, verifiers[i].ProcessResponse(nil))
		resp, err := verifiers[i].ProcessEncryptedDeal(d)
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
	deals := make([]*vss.Deal, nbVerifiers)
	for i, v := range verifiers {
		deals[i] = v.Deal()
	}

	// 5. recover
	sec, err := vss.RecoverSecret(suite, deals, nbVerifiers, vss.MinimumT(nbVerifiers))
	assert.Nil(t, err)
	require.NotNil(t, sec)
	assert.Equal(t, secret.String(), sec.String())
}

func TestVSSDealerNew(t *testing.T) {
	goodT := vss.MinimumT(nbVerifiers)
	_, err := NewDealer(suite, dealerSec, secret, verifiersPub, goodT)
	require.NoError(t, err)

	for _, badT := range []int{0, 1, -4} {
		_, err = NewDealer(suite, dealerSec, secret, verifiersPub, badT)
		assert.Error(t, err)
	}

}

func TestVSSVerifierNew(t *testing.T) {
	aggregator := NewEmptyAggregator(suite, verifiersPub)
	randIdx := rand.Int() % len(verifiersPub)
	v, err := vss.NewVerifier(suite, verifiersSec[randIdx], dealerPub, verifiersPub, aggregator)
	assert.NoError(t, err)
	assert.Equal(t, randIdx, v.Index())

	wrongKey := suite.Scalar().Pick(rng)
	_, err = vss.NewVerifier(suite, wrongKey, dealerPub, verifiersPub, aggregator)
	assert.Error(t, err)
}

func TestVSSShare(t *testing.T) {
	dealer, verifiers := genAll()
	ver := verifiers[0]
	deal, err := dealer.EncryptedDeal(0)
	require.Nil(t, err)

	resp, err := ver.ProcessEncryptedDeal(deal)
	require.NoError(t, err)
	require.NotNil(t, resp)
	require.Equal(t, vss.StatusApproval, resp.StatusApproved)
	require.Nil(t, err)

	aggr := ver.Aggregator.(*Aggregator)

	for i := 1; i < aggr.t-1; i++ {
		aggr.responses[uint32(i)] = &vss.Response{StatusApproved: vss.StatusApproval}
	}
	// not enough approvals
	assert.Nil(t, ver.Deal())

	aggr.responses[uint32(aggr.t)] = &vss.Response{StatusApproved: vss.StatusApproval}

	// Timeout all other (i>t) verifiers
	ver.SetTimeout()

	// deal not certified
	aggr.badDealer = true
	assert.Nil(t, ver.Deal())
	aggr.badDealer = false

	assert.NotNil(t, ver.Deal())

}

func TestVSSAggregatorDealCertified(t *testing.T) {
	dealer := genDealer()
	aggr := dealer.Aggregator.(*Aggregator)

	for i := 0; i < aggr.t; i++ {
		aggr.responses[uint32(i)] = &vss.Response{StatusApproved: vss.StatusApproval}
	}

	// Mark remaining verifiers as timed-out
	dealer.SetTimeout()

	assert.True(t, aggr.DealCertified())
	assert.Equal(t, suite.Point().Mul(secret, nil), dealer.SecretCommit())
	// bad dealer response
	aggr.badDealer = true
	assert.False(t, aggr.DealCertified())
	assert.Nil(t, dealer.SecretCommit())

	// reset dealer status
	aggr.badDealer = false

	// inconsistent state on purpose
	// too many complaints
	for i := 0; i < aggr.t; i++ {
		aggr.responses[uint32(i)] = &vss.Response{StatusApproved: vss.StatusComplaint}
	}
	assert.False(t, aggr.DealCertified())
}

func TestVSSVerifierDecryptDeal(t *testing.T) {
	dealer, verifiers := genAll()
	v := verifiers[0]
	d, err := dealer.PlaintextDeal(0)
	require.NoError(t, err)

	// all fine
	encD, err := dealer.EncryptedDeal(0)
	require.Nil(t, err)
	decD, err := v.DecryptDeal(encD)
	require.Nil(t, err)
	b1, _ := protobuf.Encode(d)
	b2, _ := protobuf.Encode(decD)
	assert.Equal(t, b1, b2)

	// wrong dh key
	goodDh := encD.DHKey
	encD.DHKey = suite.Point().Null()
	decD, err = v.DecryptDeal(encD)
	assert.Error(t, err)
	assert.Nil(t, decD)
	encD.DHKey = goodDh

	// wrong signature
	goodSig := encD.Signature
	encD.Signature = randomBytes(32)
	decD, err = v.DecryptDeal(encD)
	assert.Error(t, err)
	assert.Nil(t, decD)
	encD.Signature = goodSig

	// wrong ciphertext
	goodCipher := encD.Cipher
	encD.Cipher = randomBytes(len(goodCipher))
	decD, err = v.DecryptDeal(encD)
	assert.Error(t, err)
	assert.Nil(t, decD)
	encD.Cipher = goodCipher
}

func TestVSSVerifierReceiveDeal(t *testing.T) {
	dealer, verifiers := genAll()
	v := verifiers[0]
	d, err := dealer.PlaintextDeal(0)
	require.NoError(t, err)

	encD, err := dealer.EncryptedDeal(0)
	require.Nil(t, err)

	// correct deal
	resp, err := v.ProcessEncryptedDeal(encD)
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.Equal(t, vss.StatusApproval, resp.StatusApproved)
	assert.Nil(t, err)
	assert.Equal(t, v.Index(), int(resp.Index))
	assert.Equal(t, dealer.Sid(), resp.SessionID)
	msg, err := resp.Hash(suite)
	require.NoError(t, err)
	_, pub := v.Key()
	assert.Nil(t, schnorr.Verify(suite, pub, msg, resp.Signature))
	aggregator, ok := v.Aggregator.(*Aggregator)
	require.True(t, ok)
	assert.Equal(t, aggregator.responses[uint32(v.Index())], resp)

	// wrong encryption
	goodSig := encD.Signature
	encD.Signature = randomBytes(32)
	resp, err = v.ProcessEncryptedDeal(encD)
	assert.Nil(t, resp)
	assert.Error(t, err)
	encD.Signature = goodSig

	// wrong index
	goodIdx := d.SecShare.I
	d.SecShare.I = (goodIdx - 1) % uint32(nbVerifiers)
	encD, _ = dealer.EncryptedDeal(0)
	resp, err = v.ProcessEncryptedDeal(encD)
	assert.Error(t, err)
	assert.Nil(t, resp)
	d.SecShare.I = goodIdx

	// wrong commitments
	goodCommit := d.Commitments[0]
	d.Commitments[0] = suite.Point().Pick(rng)
	encD, _ = dealer.EncryptedDeal(0)
	resp, err = v.ProcessEncryptedDeal(encD)
	assert.Error(t, err)
	assert.Nil(t, resp)
	d.Commitments[0] = goodCommit

	// already seen twice
	resp, err = v.ProcessEncryptedDeal(encD)
	assert.Nil(t, resp)
	assert.Error(t, err)
	require.True(t, ok)
	aggregator.deal = nil

	// approval already existing from same origin, should never happen right ?
	aggregator.responses[uint32(v.Index())] = &vss.Response{StatusApproved: vss.StatusApproval}
	d.Commitments[0] = suite.Point().Pick(rng)
	resp, err = v.ProcessEncryptedDeal(encD)
	assert.Nil(t, resp)
	assert.Error(t, err)
	d.Commitments[0] = goodCommit

	// valid complaint
	aggregator.deal = nil
	delete(aggregator.responses, uint32(v.Index()))
	resp, err = v.ProcessEncryptedDeal(encD)
	require.NoError(t, err)
	assert.NotNil(t, resp)
	assert.Equal(t, vss.StatusComplaint, resp.StatusApproved)
	assert.Nil(t, err)
}

func TestVSSAggregatorVerifyJustification(t *testing.T) {
	dealer, verifiers := genAll()
	v := verifiers[0]
	d, err := dealer.PlaintextDeal(0)
	require.NoError(t, err)

	wrongV := suite.Scalar().Pick(rng)
	goodV := d.SecShare.V
	d.SecShare.V = wrongV
	encD, _ := dealer.EncryptedDeal(0)
	resp, err := v.ProcessEncryptedDeal(encD)
	require.NoError(t, err)
	assert.NotNil(t, resp)
	assert.Equal(t, vss.StatusComplaint, resp.StatusApproved)
	assert.Nil(t, err)

	aggregator, ok := v.Aggregator.(*Aggregator)
	assert.True(t, ok)
	assert.Equal(t, aggregator.responses[uint32(v.Index())], resp)
	// in tests, pointers point to the same underlying share...
	d.SecShare.V = goodV

	j, err := dealer.ProcessResponse(resp)
	assert.Nil(t, err)

	// invalid deal justified
	goodV = j.Deal.SecShare.V
	j.Deal.SecShare.V = wrongV
	err = v.ProcessJustification(j)
	assert.Error(t, err)
	assert.True(t, aggregator.badDealer)
	j.Deal.SecShare.V = goodV
	aggregator.badDealer = false

	// valid complaint
	assert.Nil(t, v.ProcessJustification(j))

	// invalid complaint
	resp.SessionID = randomBytes(len(resp.SessionID))
	badJ, err := dealer.ProcessResponse(resp)
	assert.Nil(t, badJ)
	assert.Error(t, err)
	resp.SessionID = dealer.Sid()

	// no complaints for this justification before
	delete(aggregator.responses, uint32(v.Index()))
	assert.Error(t, v.ProcessJustification(j))
	aggregator.responses[uint32(v.Index())] = resp

}

func TestVSSAggregatorVerifyResponseDuplicate(t *testing.T) {
	dealer, verifiers := genAll()
	v1 := verifiers[0]
	v2 := verifiers[1]
	encD1, _ := dealer.EncryptedDeal(0)
	encD2, _ := dealer.EncryptedDeal(1)

	resp1, err := v1.ProcessEncryptedDeal(encD1)
	assert.Nil(t, err)
	assert.NotNil(t, resp1)
	assert.Equal(t, vss.StatusApproval, resp1.StatusApproved)

	resp2, err := v2.ProcessEncryptedDeal(encD2)
	assert.Nil(t, err)
	assert.NotNil(t, resp2)
	assert.Equal(t, vss.StatusApproval, resp2.StatusApproved)

	err = v1.ProcessResponse(resp2)
	v1Aggregator, ok := v1.Aggregator.(*Aggregator)
	require.True(t, ok)
	assert.Nil(t, err)
	r, ok := v1Aggregator.responses[uint32(v2.Index())]
	assert.True(t, ok)
	assert.Equal(t, resp2, r)

	err = v1.ProcessResponse(resp2)
	assert.Error(t, err)

	delete(v1Aggregator.responses, uint32(v2.Index()))
	v1Aggregator.responses[uint32(v2.Index())] = &vss.Response{StatusApproved: vss.StatusApproval}
	err = v1.ProcessResponse(resp2)
	assert.Error(t, err)
}

func TestVSSAggregatorVerifyResponse(t *testing.T) {
	dealer, verifiers := genAll()
	v := verifiers[0]
	deal, err := dealer.PlaintextDeal(0)
	assert.NoError(t, err)
	wrongSec, _ := genPair()
	deal.SecShare.V = wrongSec
	encD, _ := dealer.EncryptedDeal(0)
	// valid complaint
	resp, err := v.ProcessEncryptedDeal(encD)
	assert.Nil(t, err)
	assert.NotNil(t, resp)
	assert.Equal(t, vss.StatusComplaint, resp.StatusApproved)
	assert.NotNil(t, v.Aggregator)
	assert.Equal(t, resp.SessionID, dealer.Sid())

	aggr, ok := v.Aggregator.(*Aggregator)
	require.True(t, ok)
	r, ok := aggr.responses[uint32(v.Index())]
	assert.True(t, ok)
	assert.Equal(t, vss.StatusComplaint, r.StatusApproved)

	// wrong index
	resp.Index = uint32(len(verifiersPub))
	msg, err := resp.Hash(suite)
	require.NoError(t, err)
	longterm, _ := v.Key()
	sig, err := schnorr.Sign(suite, longterm, msg)
	assert.NoError(t, err)
	resp.Signature = sig
	assert.Error(t, v.VerifyResponse(resp))
	resp.Index = 0

	// wrong signature
	goodSig := resp.Signature
	resp.Signature = randomBytes(len(goodSig))
	assert.Error(t, v.VerifyResponse(resp))
	resp.Signature = goodSig

	// wrongID
	wrongID := randomBytes(len(resp.SessionID))
	goodID := resp.SessionID
	resp.SessionID = wrongID
	assert.Error(t, v.VerifyResponse(resp))
	resp.SessionID = goodID
}

func TestVSSAggregatorAllResponses(t *testing.T) {
	dealer := genDealer()
	aggr, ok := dealer.Aggregator.(*Aggregator)
	require.True(t, ok)

	for i := 0; i < aggr.t; i++ {
		aggr.responses[uint32(i)] = &vss.Response{StatusApproved: vss.StatusApproval}
	}
	assert.False(t, aggr.DealCertified())

	for i := aggr.t; i < nbVerifiers; i++ {
		aggr.responses[uint32(i)] = &vss.Response{StatusApproved: vss.StatusApproval}
	}

	assert.True(t, aggr.DealCertified())
	assert.Equal(t, suite.Point().Mul(secret, nil), dealer.SecretCommit())
}

func TestVSSDealerTimeout(t *testing.T) {
	dealer := genDealer()
	aggr, ok := dealer.Aggregator.(*Aggregator)
	require.True(t, ok)

	for i := 0; i < aggr.t; i++ {
		aggr.responses[uint32(i)] = &vss.Response{StatusApproved: vss.StatusApproval}
	}
	require.False(t, aggr.DealCertified())

	// Tell dealer to consider other verifiers timed-out
	dealer.SetTimeout()

	// Deal should be certified
	require.True(t, aggr.DealCertified())
	require.NotNil(t, dealer.SecretCommit())
}

func TestVSSVerifierTimeout(t *testing.T) {
	dealer, verifiers := genAll()
	v := verifiers[0]

	encDeal, err := dealer.EncryptedDeal(0)

	require.Nil(t, err)

	// Make verifier create it's Aggregator by processing EncDeal
	resp, err := v.ProcessEncryptedDeal(encDeal)
	require.NotNil(t, resp)
	require.Nil(t, err)

	aggr, ok := v.Aggregator.(*Aggregator)
	require.True(t, ok)

	// Add t responses
	for i := 0; i < aggr.t; i++ {
		aggr.responses[uint32(i)] = &vss.Response{StatusApproved: vss.StatusApproval}
	}
	assert.False(t, aggr.DealCertified())

	// Trigger time out, thus adding StatusComplaint to all
	// remaining verifiers
	v.SetTimeout()

	// Deal must be certified now
	assert.True(t, aggr.DealCertified())
	assert.NotNil(t, v.Deal())
}

func TestVSSAggregatorVerifyDeal(t *testing.T) {
	dealer := genDealer()
	aggr, ok := dealer.Aggregator.(*Aggregator)
	require.True(t, ok)
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
	goodI := deal.SecShare.I
	deal.SecShare.I = goodI + 1
	assert.Error(t, aggr.VerifyDeal(deal, false))
	deal.SecShare.I = goodI

	// index not in bounds
	deal.SecShare.I = uint32(len(verifiersPub))
	assert.Error(t, aggr.VerifyDeal(deal, false))

	// shares invalid in respect to the commitments
	wrongSec, _ := genPair()
	deal.SecShare.V = wrongSec
	assert.Error(t, aggr.VerifyDeal(deal, false))
}

func TestVSSAggregatorAddComplaint(t *testing.T) {
	dealer := genDealer()
	aggr, ok := dealer.Aggregator.(*Aggregator)
	require.True(t, ok)

	var idx uint32 = 1
	c := &vss.Response{
		Index:          idx,
		StatusApproved: vss.StatusComplaint,
	}
	// ok
	assert.Nil(t, aggr.AddResponse(c))
	assert.Equal(t, aggr.responses[idx], c)

	// response already there
	assert.Error(t, aggr.AddResponse(c))
	delete(aggr.responses, idx)

}

func TestVSSSessionID(t *testing.T) {
	dealer, _ := NewDealer(suite, dealerSec, secret, verifiersPub, vssThreshold)
	deal, err := dealer.PlaintextDeal(0)
	require.NoError(t, err)
	commitments := deal.Commitments
	sid, err := vss.SessionID(suite, dealerPub, verifiersPub, commitments, dealer.Threshold())
	assert.NoError(t, err)

	sid2, err2 := vss.SessionID(suite, dealerPub, verifiersPub, commitments, dealer.Threshold())
	assert.NoError(t, err2)
	assert.Equal(t, sid, sid2)

	wrongDealerPub := suite.Point().Add(dealerPub, dealerPub)

	sid3, err3 := vss.SessionID(suite, wrongDealerPub, verifiersPub, commitments, dealer.Threshold())
	assert.NoError(t, err3)
	assert.NotEqual(t, sid3, sid2)
}

func TestVSSFindPub(t *testing.T) {
	p, ok := vss.FindPub(verifiersPub, 0)
	assert.True(t, ok)
	assert.Equal(t, verifiersPub[0], p)

	p, ok = vss.FindPub(verifiersPub, uint32(len(verifiersPub)))
	assert.False(t, ok)
	assert.Nil(t, p)
}

func TestVSSDHExchange(t *testing.T) {
	pub := suite.Point().Base()
	priv := suite.Scalar().Pick(rng)
	point := vss.DhExchange(suite, priv, pub)
	assert.Equal(t, pub.Mul(priv, nil).String(), point.String())
}

func TestVSSContext(t *testing.T) {
	c, err := vss.Context(suite, dealerPub, verifiersPub)
	require.NoError(t, err)
	assert.Len(t, c, vss.KeySize)
}

func genPair() (kyber.Scalar, kyber.Point) {
	secret := suite.Scalar().Pick(suite.RandomStream())
	public := suite.Point().Mul(secret, nil)
	return secret, public
}

func genCommits(n int) ([]kyber.Scalar, []kyber.Point) {
	var secrets = make([]kyber.Scalar, n)
	var publics = make([]kyber.Point, n)
	for i := 0; i < n; i++ {
		secrets[i], publics[i] = genPair()
	}
	return secrets, publics
}

func genDealer() *vss.Dealer {
	d, _ := NewDealer(suite, dealerSec, secret, verifiersPub, vssThreshold)
	return d
}

func genAll() (*vss.Dealer, []*vss.Verifier) {
	dealer := genDealer()
	var verifiers = make([]*vss.Verifier, nbVerifiers)
	for i := 0; i < nbVerifiers; i++ {
		aggregator := NewEmptyAggregator(suite, verifiersPub)
		v, _ := vss.NewVerifier(suite, verifiersSec[i], dealerPub, verifiersPub, aggregator)
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
