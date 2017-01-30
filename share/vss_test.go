package share

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

var reader = random.Stream

var suite = ed25519.NewAES128SHA256Ed25519(false)

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

/*func genAllFinish(npAp, nbCo, nbDr int) (*Dealer, []*Verifier, []*Approval, []*Complaints) {*/
//dealer, verifiers := genAll()
//if nbAp+nbCo != nbVerifiers {
//panic("genAllFinish is given some wrong arguments")
//} else if nbDr > nbCo {
//panic("genAllFinish is given some wrong arguments")
//}
//var approvals = make([]*Approval, nbAp)
//var complaints = make([]*Complaints, nbCo)
//for i := 0; i < nbAp; i++ {
//approvals[i], _, _ = verifiers[i].ReceiveDeal(dealer.deals[i])
//}
//for j := nbAp; j < nbVerifiers; j++ {
//_, complaints[j], _ = verifiers[j].ReceiveDeal(dealer.deals[j])
//}
/*}*/

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
	vssThreshold = minimumT(verifiersPub)
}

func TestVSSDealerNew(t *testing.T) {
	goodT := minimumT(verifiersPub)
	_, err := NewDealer(suite, dealerSec, secret, verifiersPub, reader, goodT)
	assert.NoError(t, err)

	for badT := range []int{goodT - 1, len(verifiersPub) + 1, -4} {
		_, err = NewDealer(suite, dealerSec, secret, verifiersPub, reader, badT)
		assert.Error(t, err)
	}
}

func TestVSSVerifierNew(t *testing.T) {
	randIdx := rand.Int() % len(verifiersPub)
	_, err := NewVerifier(suite, verifiersSec[randIdx], dealerPub, verifiersPub)
	assert.NoError(t, err)

	wrongKey := suite.Scalar().Pick(reader)
	_, err = NewVerifier(suite, wrongKey, dealerPub, verifiersPub)
	assert.Error(t, err)
}

func TestVSSShare(t *testing.T) {
	dealer, verifiers := genAll()
	ver := verifiers[0]
	ap, c, err := ver.ReceiveDeal(dealer.deals[0])
	require.NotNil(t, ap)
	require.Nil(t, c)
	require.Nil(t, err)

	aggr := ver.aggregator

	for i := 1; i < aggr.t-1; i++ {
		aggr.approvals[verifiersPub[i].String()] = &Approval{}
	}
	// not enough approvals
	assert.Nil(t, ver.Share())
	aggr.approvals[verifiersPub[aggr.t].String()] = &Approval{}
	// deal not certified
	aggr.badDealer = true
	assert.Nil(t, ver.Share())
	aggr.badDealer = false

	assert.NotNil(t, ver.Share())

}

func TestVSSAggregatorEnoughApprovals(t *testing.T) {
	dealer := genDealer()
	aggr := dealer.aggregator
	// just below
	for i := 0; i < aggr.t-1; i++ {
		aggr.approvals[verifiersPub[i].String()] = &Approval{}
	}
	assert.False(t, aggr.EnoughApprovals())

	aggr.approvals[verifiersPub[aggr.t].String()] = &Approval{}
	assert.True(t, aggr.EnoughApprovals())

	for i := aggr.t + 1; i < nbVerifiers; i++ {
		aggr.approvals[verifiersPub[i].String()] = &Approval{}
	}
	assert.True(t, aggr.EnoughApprovals())
}

func TestVSSAggregatorDealCertified(t *testing.T) {
	dealer := genDealer()
	aggr := dealer.aggregator

	for i := 0; i < aggr.t; i++ {
		aggr.approvals[verifiersPub[i].String()] = &Approval{}
	}
	assert.True(t, aggr.DealCertified())
	// bad dealer response
	aggr.badDealer = true
	assert.False(t, aggr.DealCertified())
	// inconsistent state on purpose
	// too much complaints
	for i := 0; i < aggr.t; i++ {
		aggr.complaints[verifiersPub[i].String()] = &Complaint{}
	}
	assert.False(t, aggr.DealCertified())
}

func TestVSSVerifierReceiveDeal(t *testing.T) {
	dealer, verifiers := genAll()
	v := verifiers[0]
	d := dealer.deals[0]

	// correct deal
	ap, c, err := v.ReceiveDeal(d)
	require.NotNil(t, ap)
	assert.Nil(t, c)
	assert.Nil(t, err)
	assert.Equal(t, v.pub.String(), ap.Public.String())
	assert.Equal(t, dealer.sid, ap.SessionID)
	assert.Nil(t, sign.VerifySchnorr(suite, v.pub, ap.SessionID, ap.Signature))
	assert.Equal(t, v.approvals[v.pub.String()], ap)

	// wrong index
	goodIdx := d.SecShare.I
	d.SecShare.I = (goodIdx - 1) % nbVerifiers
	_, c, err = v.ReceiveDeal(d)
	assert.Error(t, err)
	assert.Nil(t, c)
	d.SecShare.I = goodIdx

	// wrong commitments
	goodCommit := d.Commitments[0]
	d.Commitments[0], _ = suite.Point().Pick(nil, random.Stream)
	ap, c, err = v.ReceiveDeal(d)
	assert.Error(t, err)
	assert.Nil(t, c)
	assert.Nil(t, ap)
	d.Commitments[0] = goodCommit

	// already seen twice
	ap, c, err = v.ReceiveDeal(d)
	assert.Nil(t, c)
	assert.Error(t, err)
	assert.Nil(t, ap)
	v.aggregator.deal = nil

	// approval already existing from same origin, should never happen right ?
	v.aggregator.approvals[v.pub.String()] = &Approval{}
	d.Commitments[0], _ = suite.Point().Pick(nil, random.Stream)
	ap, c, err = v.ReceiveDeal(d)
	assert.Nil(t, c)
	assert.Error(t, err)
	assert.Nil(t, ap)
	d.Commitments[0] = goodCommit

	// valid complaint
	v.aggregator.deal = nil
	delete(v.aggregator.approvals, v.pub.String())
	d.RndShare.V = suite.Scalar().SetBytes(randomBytes(32))
	ap, c, err = v.ReceiveDeal(d)
	assert.Nil(t, ap)
	assert.NotNil(t, c)
	assert.Error(t, err)
}

func TestVSSAggregatorDealerResponse(t *testing.T) {
	dealer, verifiers := genAll()
	v := verifiers[0]
	deals := dealer.Deals()
	d := deals[0]

	wrongV := suite.Scalar().Pick(random.Stream)
	goodV := d.SecShare.V
	d.SecShare.V = wrongV
	ap, c, err := v.ReceiveDeal(d)
	assert.Nil(t, ap)
	assert.NotNil(t, c)
	assert.Error(t, err)
	assert.Equal(t, v.complaints[c.Public.String()], c)

	c.Deal = &Deal{
		SessionID:   deals[0].SessionID,
		SecShare:    deals[0].SecShare,
		RndShare:    deals[0].RndShare,
		T:           deals[0].T,
		Commitments: deals[0].Commitments,
	}
	c.Deal.SecShare.V = wrongV
	// valid complaint
	dr, err := dealer.ReceiveComplaint(c)
	d.SecShare.V = goodV // in tests, pointers point to the same underlying share..
	assert.Nil(t, err)
	assert.Equal(t, dr.Deal, d)
	assert.Nil(t, v.ReceiveDealerResponse(dr))

	// invalid  complaint
	c.SessionID = randomBytes(len(c.SessionID))
	badDr, err := dealer.ReceiveComplaint(c)
	assert.Nil(t, badDr)
	assert.Error(t, err)
	c.SessionID = dealer.sid

	// no complaints for this DR before
	delete(v.aggregator.complaints, v.pub.String())
	assert.Error(t, v.ReceiveDealerResponse(dr))
	v.aggregator.complaints[v.pub.String()] = c

	// invalid deal revealed
	goodV = dr.Deal.SecShare.V
	dr.Deal.SecShare.V = wrongV
	assert.Error(t, v.ReceiveDealerResponse(dr))
	assert.True(t, v.aggregator.badDealer)
	dr.Deal.SecShare.V = goodV
}

func TestVSSAggregatorVerifyComplaint(t *testing.T) {
	dealer, verifiers := genAll()
	v := verifiers[0]
	deal := dealer.deals[0]
	goodSec := deal.SecShare.V
	wrongSec, _ := genPair()
	deal.SecShare.V = wrongSec

	// valid complaint
	_, c, err := v.ReceiveDeal(deal)
	aggr := v.aggregator
	assert.Error(t, err)
	assert.NotNil(t, c)
	assert.NotNil(t, v.aggregator)
	assert.Equal(t, c.SessionID, dealer.sid)
	_, ok := aggr.complaints[v.pub.String()]
	assert.True(t, ok)

	// give a valid deal
	deal.SecShare.V = goodSec
	c.Deal = deal
	assert.Error(t, aggr.verifyComplaint(c))

	// wrong index
	priv, pub := genPair()
	sig, err := sign.Schnorr(suite, priv, c.SessionID)
	require.Nil(t, err)
	c.Public = pub
	c.Signature = sig
	assert.Error(t, aggr.verifyComplaint(c))
	c.Public = verifiersPub[0]

	// wrong signature
	var goodSig = make([]byte, len(c.Signature))
	copy(goodSig, c.Signature)
	c.Signature[rand.Int()%len(c.Signature)] = byte(rand.Int())
	assert.Error(t, aggr.verifyComplaint(c))
	c.Signature = goodSig

	// wrongID
	wrongID := randomBytes(len(c.SessionID))
	goodID := c.SessionID
	c.SessionID = wrongID
	assert.Error(t, aggr.verifyComplaint(c))
	c.SessionID = goodID
}

func TestVSSAggregatorVerifyDeal(t *testing.T) {
	dealer := genDealer()
	aggr := newAggregator(suite, verifiersPub, dealer.commitments, dealer.t, dealer.sessionID)
	deals := dealer.Deals()

	// OK
	deal := deals[0]
	err := aggr.verifyDeal(deal, true)
	assert.NoError(t, err)
	assert.NotNil(t, aggr.deal)

	// already received deal
	err = aggr.verifyDeal(deal, true)
	assert.Error(t, err)

	// wrong T
	wrongT := uint32(nbVerifiers / 3)
	goodT := deal.T
	deal.T = wrongT
	assert.Error(t, aggr.verifyDeal(deal, false))
	deal.T = goodT

	// wrong SessionID
	goodSid := deal.SessionID
	deal.SessionID = make([]byte, 32)
	assert.Error(t, aggr.verifyDeal(deal, false))
	deal.SessionID = goodSid

	// index different in one share
	goodI := deal.RndShare.I
	deal.RndShare.I = goodI + 1
	assert.Error(t, aggr.verifyDeal(deal, false))
	deal.RndShare.I = goodI

	// index not in bounds
	deal.SecShare.I = -1
	assert.Error(t, aggr.verifyDeal(deal, false))
	deal.SecShare.I = len(verifiersPub)
	assert.Error(t, aggr.verifyDeal(deal, false))

	// shares invalid in respect to the commitments
	wrongSec, _ := genPair()
	deal.SecShare.V = wrongSec
	assert.Error(t, aggr.verifyDeal(deal, false))
}

func TestVSSAggregatorVerifyApproval(t *testing.T) {
	dealer, verifiers := genAll()
	deals := dealer.Deals()
	v := verifiers[0]

	// ok
	ap, c, err := v.ReceiveDeal(deals[0])
	assert.Nil(t, c)
	assert.Nil(t, err)
	assert.NotNil(t, ap)

	aggr := v.aggregator
	// nil deal
	aggr.deal = nil
	assert.Error(t, aggr.verifyApproval(ap))
	aggr.deal = deals[0]
	// twice approval
	assert.Error(t, aggr.verifyApproval(ap))
	delete(aggr.approvals, v.pub.String())
	// wrong SID
	ap.SessionID = randomBytes(len(ap.SessionID))
	assert.Error(t, aggr.verifyApproval(ap))
	ap.SessionID = dealer.sid
	// wrong signature
	goodSig := ap.Signature
	wrongSig := randomBytes(len(goodSig))
	ap.Signature = wrongSig
	assert.Error(t, aggr.verifyApproval(ap))
	ap.Signature = goodSig
}

func TestVSSAggregatorAddComplaint(t *testing.T) {
	dealer := genDealer()
	aggr := dealer.aggregator

	c := &Complaint{
		Public: verifiersPub[0],
	}
	// ok
	assert.Nil(t, aggr.addComplaint(c))
	assert.Equal(t, aggr.complaints[c.Public.String()], c)

	// complaint already there
	assert.Error(t, aggr.addComplaint(c))
	delete(aggr.complaints, c.Public.String())

	// approval same origin
	aggr.approvals[verifiersPub[0].String()] = &Approval{}
	assert.Error(t, aggr.addComplaint(c))
}

func TestVSSAggregatorAddApproval(t *testing.T) {
	dealer := genDealer()
	aggr := dealer.aggregator

	ap := &Approval{
		Public: verifiersPub[0],
	}
	// ok
	assert.Nil(t, aggr.addApproval(ap))
	assert.Equal(t, aggr.approvals[ap.Public.String()], ap)

	// approval already existing
	assert.Error(t, aggr.addApproval(ap))
	delete(aggr.approvals, ap.Public.String())

	// complaint same origin
	aggr.complaints[ap.Public.String()] = &Complaint{}
	assert.Error(t, aggr.addApproval(ap))
}

func TestVSSSessionID(t *testing.T) {
	dealer, _ := NewDealer(suite, dealerSec, secret, verifiersPub, reader, vssThreshold)
	sid, err := sessionID(dealerPub, verifiersPub, dealer.commitments, dealer.t)
	assert.NoError(t, err)

	sid2, err2 := sessionID(dealerPub, verifiersPub, dealer.commitments, dealer.t)
	assert.NoError(t, err2)
	assert.Equal(t, sid, sid2)

	wrongDealerPub := suite.Point().Add(dealerPub, dealerPub)

	sid3, err3 := sessionID(wrongDealerPub, verifiersPub, dealer.commitments, dealer.t)
	assert.NoError(t, err3)
	assert.NotEqual(t, sid3, sid2)
}

func TestVSSFindIndex(t *testing.T) {
	randIdx := rand.Int() % len(verifiersPub)
	i, ok := findIndex(verifiersPub, verifiersPub[randIdx])
	assert.True(t, ok)
	assert.Equal(t, randIdx, i)

	_, wrongPub := genPair()
	i, ok = findIndex(verifiersPub, wrongPub)
	assert.False(t, ok)
}
