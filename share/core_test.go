package share_test

import (
	"testing"

	"github.com/dedis/crypto/abstract"
	"github.com/dedis/crypto/edwards"
	"github.com/dedis/crypto/random"
	"github.com/dedis/crypto/share"
)

var group abstract.Group = new(edwards.ExtendedCurve).Init(edwards.Param25519(), false)
var threshold int = 10
var numShares int = 20

func TestRecovery(t *testing.T) {

	secret := group.Scalar().Pick(random.Stream)
	poly := share.NewPriPoly(group, threshold, secret, random.Stream)
	shares := poly.Shares(numShares)

	recovered, err := share.RecoverSecret(group, shares, threshold)
	if err != nil {
		t.Fatal(err)
	}

	if !secret.Equal(recovered) {
		t.Fatal("Recovered secret does not match initial value")
	}

}
