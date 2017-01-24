package share_test

import (
	"testing"

	"github.com/dedis/crypto/abstract"
	"github.com/dedis/crypto/edwards"
	"github.com/dedis/crypto/random"
	"github.com/dedis/crypto/share"
)

var group abstract.Group = new(edwards.ExtendedCurve).Init(edwards.Param25519(), false)
var numShares int = 20
var threshold int = 11

func TestSecretRecovery(t *testing.T) {

	poly := share.NewPriPoly(group, threshold, nil, random.Stream)
	shares := poly.Shares(numShares)

	recovered, err := share.RecoverSecret(group, shares, threshold)
	if err != nil {
		t.Fatal(err)
	}

	if !recovered.Equal(poly.GetSecret()) {
		t.Fatal("Recovered secret does not match initial value")
	}

}

func TestSecretRecoveryDelete(t *testing.T) {

	poly := share.NewPriPoly(group, threshold, nil, random.Stream)
	shares := poly.Shares(numShares)

	// Delete a few shares
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

	if !recovered.Equal(poly.GetSecret()) {
		t.Fatal("Recovered secret does not match initial value")
	}

}

func TestSecretRecoveryDeleteFail(t *testing.T) {

	poly := share.NewPriPoly(group, threshold, nil, random.Stream)
	shares := poly.Shares(numShares)

	// Delete one more share than acceptable
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

func TestPublicCheck(t *testing.T) {

	priPoly := share.NewPriPoly(group, threshold, nil, random.Stream)
	priShares := priPoly.Shares(numShares)
	pubPoly := priPoly.Commit(nil)

	for i, share := range priShares {
		if !pubPoly.Check(share) {
			t.Fatalf("Private share %v not valid with respect to the public commitment polynomial", i)
		}
	}

}

func TestPublicRecovery(t *testing.T) {

	priPoly := share.NewPriPoly(group, threshold, nil, random.Stream)
	pubPoly := priPoly.Commit(nil)
	pubShares := pubPoly.Shares(numShares)

	recovered, err := share.RecoverCommit(group, pubShares, threshold)
	if err != nil {
		t.Fatal(err)
	}

	if !recovered.Equal(pubPoly.GetCommit()) {
		t.Fatal("Recovered commi does not match initial value")
	}

}

func TestPublicRecoveryDelete(t *testing.T) {

	priPoly := share.NewPriPoly(group, threshold, nil, random.Stream)
	pubPoly := priPoly.Commit(nil)
	shares := pubPoly.Shares(numShares)

	// Delete a few shares
	shares[2] = nil
	shares[5] = nil
	shares[7] = nil
	shares[8] = nil
	shares[10] = nil
	shares[15] = nil
	shares[16] = nil
	shares[17] = nil
	shares[19] = nil

	recovered, err := share.RecoverCommit(group, shares, threshold)
	if err != nil {
		t.Fatal(err)
	}

	if !recovered.Equal(pubPoly.GetCommit()) {
		t.Fatal("Recovered commit does not match initial value")
	}

}

func TestPublicRecoveryDeleteFail(t *testing.T) {

	priPoly := share.NewPriPoly(group, threshold, nil, random.Stream)
	pubPoly := priPoly.Commit(nil)
	shares := pubPoly.Shares(numShares)

	// Delete one more share than acceptable
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

	_, err := share.RecoverCommit(group, shares, threshold)
	if err == nil {
		t.Fatal("Recovered commit unexpectably")
	}

}

func TestAdd(t *testing.T) {

	G, _ := group.Point().Pick([]byte("G"), random.Stream)
	H, _ := group.Point().Pick([]byte("H"), random.Stream)

	p := share.NewPriPoly(group, threshold, nil, random.Stream)
	q := share.NewPriPoly(group, threshold, nil, random.Stream)

	P := p.Commit(G)
	Q := q.Commit(H)

	R, err := P.Add(Q)
	if err != nil {
		t.Fatal(err)
	}

	shares := R.Shares(numShares)
	recovered, err := share.RecoverCommit(group, shares, threshold)
	if err != nil {
		t.Fatal(err)
	}

	ps := p.GetSecret()
	qs := q.GetSecret()
	x := group.Point().Mul(G, ps)
	y := group.Point().Mul(H, qs)
	z := group.Point().Add(x, y)

	if !recovered.Equal(z) {
		t.Fatal("Homomorphic polynomial addition failed")
	}

}
