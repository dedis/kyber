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

func init() {
	verifiersSec, verifiersPub = genCommits(nbVerifiers)
	dealerSec, dealerPub = genPair()
	secret, _ = genPair()
	vssThreshold = minimumT(verifiersPub)
}

func TestVSSDealerT(t *testing.T) {
	goodT := minimumT(verifiersPub)
	_, err := NewDealer(suite, dealerSec, secret, verifiersPub, reader, goodT)
	assert.NoError(t, err)

	for badT := range []int{goodT - 1, len(verifiersPub) + 1, -4} {
		_, err = NewDealer(suite, dealerSec, secret, verifiersPub, reader, badT)
		assert.Error(t, err)
	}

}

func TestVSSVerifier(t *testing.T) {
	randIdx := rand.Int() % len(verifiersPub)
	_, err := NewVerifier(suite, verifiersSec[randIdx], dealerPub, verifiersPub)
	assert.NoError(t, err)

	wrongKey := suite.Scalar().Pick(reader)
	_, err = NewVerifier(suite, wrongKey, dealerPub, verifiersPub)
	assert.Error(t, err)
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
