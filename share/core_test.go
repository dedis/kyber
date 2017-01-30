package share

import (
	"testing"

	"github.com/dedis/crypto/edwards"
	"github.com/dedis/crypto/random"
)

var group = new(edwards.ExtendedCurve).Init(edwards.Param25519(), false)
var numShares = 10
var threshold = numShares/2 + 1

func TestSecretRecovery(t *testing.T) {

	poly := NewPriPoly(group, threshold, nil, random.Stream)
	shares := poly.Shares(numShares)

	recovered, err := RecoverSecret(group, shares, threshold, numShares)
	if err != nil {
		t.Fatal(err)
	}

	if !recovered.Equal(poly.GetSecret()) {
		t.Fatal("recovered secret does not match initial value")
	}
}

func TestSecretRecoveryDelete(t *testing.T) {

	poly := NewPriPoly(group, threshold, nil, random.Stream)
	shares := poly.Shares(numShares)

	// Corrupt a few shares
	shares[2] = nil
	shares[5] = nil
	shares[7] = nil
	shares[8] = nil

	recovered, err := RecoverSecret(group, shares, threshold, numShares)
	if err != nil {
		t.Fatal(err)
	}

	if !recovered.Equal(poly.GetSecret()) {
		t.Fatal("recovered secret does not match initial value")
	}
}

func TestSecretRecoveryDeleteFail(t *testing.T) {

	poly := NewPriPoly(group, threshold, nil, random.Stream)
	shares := poly.Shares(numShares)

	// Corrupt one more share than acceptable
	shares[1] = nil
	shares[2] = nil
	shares[5] = nil
	shares[7] = nil
	shares[8] = nil

	_, err := RecoverSecret(group, shares, threshold, numShares)
	if err == nil {
		t.Fatal("recovered secret unexpectably")
	}
}

func TestPublicCheck(t *testing.T) {

	priPoly := NewPriPoly(group, threshold, nil, random.Stream)
	priShares := priPoly.Shares(numShares)
	pubPoly := priPoly.Commit(nil)

	for i, share := range priShares {
		if !pubPoly.Check(share) {
			t.Fatalf("private share %v not valid with respect to the public commitment polynomial", i)
		}
	}
}

func TestPublicRecovery(t *testing.T) {

	priPoly := NewPriPoly(group, threshold, nil, random.Stream)
	pubPoly := priPoly.Commit(nil)
	pubShares := pubPoly.Shares(numShares)

	recovered, err := RecoverCommit(group, pubShares, threshold, numShares)
	if err != nil {
		t.Fatal(err)
	}

	if !recovered.Equal(pubPoly.GetCommit()) {
		t.Fatal("recovered commi does not match initial value")
	}
}

func TestPublicRecoveryDelete(t *testing.T) {

	priPoly := NewPriPoly(group, threshold, nil, random.Stream)
	pubPoly := priPoly.Commit(nil)
	shares := pubPoly.Shares(numShares)

	// Corrupt a few shares
	shares[2] = nil
	shares[5] = nil
	shares[7] = nil
	shares[8] = nil

	recovered, err := RecoverCommit(group, shares, threshold, numShares)
	if err != nil {
		t.Fatal(err)
	}

	if !recovered.Equal(pubPoly.GetCommit()) {
		t.Fatal("recovered commit does not match initial value")
	}
}

func TestPublicRecoveryDeleteFail(t *testing.T) {

	priPoly := NewPriPoly(group, threshold, nil, random.Stream)
	pubPoly := priPoly.Commit(nil)
	shares := pubPoly.Shares(numShares)

	// Corrupt one more share than acceptable
	shares[1] = nil
	shares[2] = nil
	shares[5] = nil
	shares[7] = nil
	shares[8] = nil

	_, err := RecoverCommit(group, shares, threshold, numShares)
	if err == nil {
		t.Fatal("recovered commit unexpectably")
	}
}

func TestPrivateAdd(t *testing.T) {

	p := NewPriPoly(group, threshold, nil, random.Stream)
	q := NewPriPoly(group, threshold, nil, random.Stream)

	r, err := p.Add(q)
	if err != nil {
		t.Fatal(err)
	}

	ps := p.GetSecret()
	qs := q.GetSecret()
	rs := group.Scalar().Add(ps, qs)

	if !rs.Equal(r.GetSecret()) {
		t.Fatal("addition of secret sharing polynomials failed")
	}
}

func TestPublicAdd(t *testing.T) {

	G, _ := group.Point().Pick([]byte("G"), random.Stream)
	H, _ := group.Point().Pick([]byte("H"), random.Stream)

	p := NewPriPoly(group, threshold, nil, random.Stream)
	q := NewPriPoly(group, threshold, nil, random.Stream)

	P := p.Commit(G)
	Q := q.Commit(H)

	R, err := P.Add(Q)
	if err != nil {
		t.Fatal(err)
	}

	shares := R.Shares(numShares)
	recovered, err := RecoverCommit(group, shares, threshold, numShares)
	if err != nil {
		t.Fatal(err)
	}

	x := P.GetCommit()
	y := Q.GetCommit()
	z := group.Point().Add(x, y)

	if !recovered.Equal(z) {
		t.Fatal("addition of public commitment polynomials failed")
	}
}
