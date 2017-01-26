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

func init() {
	verifiersSec, verifiersPub = genCommits(nbVerifiers)
	dealerSec, dealerPub = genPair()
	secret, _ = genPair()
}

func TestVSSDealerT(t *testing.T) {
	dealer, err := NewDealer(suite, dealerSec, secret, verifiersPub, reader)
	assert.NoError(t, err)
	assert.Equal(t, defaultT(verifiersPub), dealer.t)

	goodT := defaultT(verifiersPub) - 1
	_, err = NewDealerWithT(suite, dealerSec, secret, verifiersPub, reader, goodT)
	assert.NoError(t, err)

	badT := defaultT(verifiersPub) + 1
	_, err = NewDealerWithT(suite, dealerSec, secret, verifiersPub, reader, badT)
	assert.Error(t, err)
}

func TestVSSVerifier(t *testing.T) {
	randIdx := rand.Int() % len(verifiersPub)
	_, err := NewVerifier(suite, verifiersSec[randIdx], dealerPub, verifiersPub)
	assert.NoError(t, err)

	wrongKey := suite.Scalar().Pick(reader)
	_, err = NewVerifier(suite, wrongKey, dealerPub, verifiersPub)
	assert.Error(t, err)
}
