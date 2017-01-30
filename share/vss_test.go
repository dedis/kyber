package share

import (
	"math/rand"
	"testing"

	"github.com/dedis/crypto/abstract"
	"github.com/dedis/crypto/ed25519"
	"github.com/dedis/crypto/random"
	"github.com/stretchr/testify/assert"
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

func TestVSSVerifierReceiveDeal(t *testing.T) {
	/*dealer, verifiers := genAll()*/
	//v := verifiers[0]
	//d := dealer.deals[0]

	//// correct deal
	//ap, c, err := v.ReceiveDeal(d)
	//require.NotNil(t, ap)
	//assert.Nil(t, c)
	//assert.Nil(t, err)
	//assert.Equal(t, v.Pub.String(), ap.Public.String())
	//assert.Equal(t, dealer.sid, ap.SessionID)
	//sig, err := sign.Schnorr(suite, v.long, dealer.sid)
	//require.Nil(t, err)
	//assert.Equal(t, sig, ap.Signature)

	//// wrong index
	//goodIdx := d.SecShare.I
	//d.SecShare.I = (goodIdx - 1) % nbVerifiers

}

func TestVSSAggregatorVerifyComplaint(t *testing.T) {
	dealer, verifiers := genAll()
	v := verifiers[0]
	deal := dealer.deals[0]
	goodSec := deal.SecShare.V
	wrongSec, _ := genPair()
	deal.SecShare.V = wrongSec

	_, c, err := v.ReceiveDeal(deal)
	aggr := v.aggregator
	assert.Error(t, err)
	assert.NotNil(t, c)
	assert.NotNil(t, v.aggregator)
	_, ok := aggr.complaints[v.pub.String()]
	assert.True(t, ok)

	// give a valid deal
	deal.SecShare.V = goodSec
	c.Deal = deal
	assert.Error(t, aggr.verifyComplaint(c))

	// put complaint twice
	deal.SecShare.V = wrongSec
	c.Deal = deal
	assert.Error(t, aggr.verifyComplaint(c))
	delete(aggr.complaints, v.pub.String())

	// wrong index
	rndIdx := 1 + (rand.Int() % (nbVerifiers - 1))
	c.Public = verifiersPub[rndIdx]
	assert.Error(t, aggr.verifyComplaint(c))
	c.Public = verifiersPub[0]

	// wrong signature
	var goodSig = make([]byte, len(c.Signature))
	copy(goodSig, c.Signature)
	c.Signature[rand.Int()%len(c.Signature)] = byte(rand.Int())
	assert.Error(t, aggr.verifyComplaint(c))
	c.Signature = goodSig

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
