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

func TestRecoveryDelete(t *testing.T) {

	secret := group.Scalar().Pick(random.Stream)
	poly := share.NewPriPoly(group, threshold, secret, random.Stream)
	shares := poly.Shares(numShares)

	// Delete a few shares
	shares[1] = nil
	shares[2] = nil
	shares[5] = nil
	shares[7] = nil
	shares[8] = nil
	shares[10] = nil
	shares[15] = nil
	shares[16] = nil
	shares[17] = nil
	shares[19] = nil

	recovered, err := share.RecoverSecret(group, shares, threshold)
	if err != nil {
		t.Fatal(err)
	}

	if !secret.Equal(recovered) {
		t.Fatal("Recovered secret does not match initial value")
	}

}

func TestRecoveryDeleteFail(t *testing.T) {

	secret := group.Scalar().Pick(random.Stream)
	poly := share.NewPriPoly(group, threshold, secret, random.Stream)
	shares := poly.Shares(numShares)

	// Delete one more share than acceptable
	shares[0] = nil
	shares[1] = nil
	shares[2] = nil
	shares[5] = nil
	shares[7] = nil
	shares[8] = nil
	shares[10] = nil
	shares[15] = nil
	shares[16] = nil
	shares[17] = nil
	shares[19] = nil

	_, err := share.RecoverSecret(group, shares, threshold)
	if err == nil {
		t.Fatal("Recovered secret unexpectably")
	}

}
