package pvss

import (
	"testing"

	"github.com/stretchr/testify/require"
	"go.dedis.ch/kyber/v4"
	"go.dedis.ch/kyber/v4/group/edwards25519"
	"go.dedis.ch/kyber/v4/proof/dleq"
	"go.dedis.ch/kyber/v4/share"
)

type Config struct {
	suite Suite
	n     uint32
	t     uint32
	H     kyber.Point
	X     []kyber.Point  // trustee public keys
	x     []kyber.Scalar // trustee private keys
}

func getConfig(n, t uint32) Config {
	suite := edwards25519.NewBlakeSHA256Ed25519()
	conf := Config{
		suite: suite,
		n:     n,
		t:     t,
		H:     suite.Point().Pick(suite.XOF([]byte("H"))),
		X:     make([]kyber.Point, n),
		x:     make([]kyber.Scalar, n),
	}

	for i := uint32(0); i < n; i++ {
		conf.x[i] = suite.Scalar().Pick(suite.RandomStream())
		conf.X[i] = suite.Point().Mul(conf.x[i], nil)
	}

	return conf
}

type KED struct {
	K []kyber.Point  // good public keys
	E []*PubVerShare // good encrypted shares
	D []*PubVerShare // good decrypted shares
}

func ComputeKED(conf Config, l uint32, pubPoly *share.PubPoly, encShares []*PubVerShare, sH []kyber.Point) (*KED, error) {
	var K []kyber.Point  // good public keys
	var E []*PubVerShare // good encrypted shares
	var D []*PubVerShare // good decrypted shares

	globalChallenge, err := computeGlobalChallenge(conf.suite, l, pubPoly, encShares)
	if err != nil {
		return &KED{}, err
	}

	for i := uint32(0); i < conf.n; i++ {
		if ds, err := DecShare(conf.suite, conf.H, conf.X[i], sH[i], conf.x[i], globalChallenge, encShares[i]); err == nil {
			K = append(K, conf.X[i])
			E = append(E, encShares[i])
			D = append(D, ds)
		}
	}

	return &KED{K: K, E: E, D: D}, nil
}

func EncryptAndShare(conf Config, secret kyber.Scalar) (*share.PubPoly, []*PubVerShare, []kyber.Point, error) {
	// (1) Share distribution (dealer)
	encShares, pubPoly, err := EncShares(conf.suite, conf.H, conf.X, secret, conf.t)
	if err != nil {
		return nil, nil, nil, err
	}

	// (2) Share decryption (trustees)
	sH := make([]kyber.Point, conf.n)
	for i := uint32(0); i < conf.n; i++ {
		sH[i] = pubPoly.Eval(encShares[i].S.I).V
	}

	return pubPoly, encShares, sH, nil
}

func RunPVSS(n, t uint32) (Config, kyber.Scalar, *KED, error) {
	conf := getConfig(n, t)

	// Scalar of shared secret
	secret := conf.suite.Scalar().Pick(conf.suite.RandomStream())

	pubPoly, encShares, sH, err := EncryptAndShare(conf, secret)
	if err != nil {
		return conf, secret, nil, err
	}

	ked, err := ComputeKED(conf, n, pubPoly, encShares, sH)
	return conf, secret, ked, err
}

func TestComputePolyCommitments(test *testing.T) {
	n := uint32(20)
	t := uint32(15)
	conf := getConfig(n, t)
	secret := conf.suite.Scalar().Pick(conf.suite.RandomStream())
	priPoly := share.NewPriPoly(conf.suite, t, secret, conf.suite.RandomStream())

	x := make([]kyber.Scalar, n) // trustee private keys
	X := make([]kyber.Point, n)  // trustee public keys
	for i := uint32(0); i < n; i++ {
		x[i] = conf.suite.Scalar().Pick(conf.suite.RandomStream())
		X[i] = conf.suite.Point().Mul(x[i], nil)
	}

	pubPoly := priPoly.Commit(conf.H)
	// Create secret set of shares
	priShares := priPoly.Shares(n)

	// Prepare data for encryption consistency proofs ...
	indices := make([]uint32, n)
	values := make([]kyber.Scalar, n)
	HS := make([]kyber.Point, n)
	for i := uint32(0); i < n; i++ {
		indices[i] = priShares[i].I
		values[i] = priShares[i].V
		HS[i] = conf.H
	}

	_, expectedComm, _, err := dleq.NewDLEQProofBatch(conf.suite, HS, X, values)
	require.NoError(test, err)

	_, com := pubPoly.Info()
	actualComm := computeCommitments(conf.suite, n, com)

	require.Equal(test, n, uint32(len(expectedComm)))
	require.Equal(test, len(expectedComm), len(actualComm))

	for i := uint32(0); i < n; i++ {
		require.Equal(test, expectedComm[i].String(), actualComm[i].String())
	}
}

func TestPVSS(test *testing.T) {
	n := uint32(10)
	conf, secret, ked, err := RunPVSS(n, 2*n/3+1)
	require.NoError(test, err)
	G := conf.suite.Point().Base()

	// (3) Check decrypted shares and recover secret if possible (dealer/3rd party)
	recovered, err := RecoverSecret(conf.suite, G, ked.K, ked.E, ked.D, conf.t, n)
	require.NoError(test, err)
	require.True(test, conf.suite.Point().Mul(secret, nil).Equal(recovered))
}

func TestPVSSDelete(test *testing.T) {
	n := uint32(10)
	t := 2*n/3 + 1
	conf := getConfig(n, t)
	G := conf.suite.Point().Base()

	// Scalar of shared secret
	secret := conf.suite.Scalar().Pick(conf.suite.RandomStream())

	pubPoly, encShares, sH, err := EncryptAndShare(conf, secret)
	require.NoError(test, err)

	l := uint32(len(conf.X))
	ked, err := ComputeKED(conf, l, pubPoly, encShares, sH)
	require.NoError(test, err)

	// Corrupt some of the decrypted shares
	ked.D[0].S.V = conf.suite.Point().Null()
	ked.D[1].S.V = conf.suite.Point().Null()
	ked.D[2].S.V = conf.suite.Point().Null()

	// (3) Check decrypted shares and recover secret if possible (dealer/3rd party)
	recovered, err := RecoverSecret(conf.suite, G, ked.K, ked.E, ked.D, t, n)
	require.NoError(test, err)
	require.True(test, conf.suite.Point().Mul(secret, nil).Equal(recovered))
}

func TestPVSSDeleteFail(test *testing.T) {
	n := uint32(10)
	conf, _, ked, err := RunPVSS(n, 2*n/3+1)
	require.NoError(test, err)
	G := conf.suite.Point().Base()

	// Corrupt enough decrypted shares to make the secret unrecoverable
	ked.D[0].S.V = conf.suite.Point().Null()
	ked.D[1].S.V = conf.suite.Point().Null()
	ked.D[2].S.V = conf.suite.Point().Null()
	ked.D[3].S.V = conf.suite.Point().Null()

	// (3) Check decrypted shares and recover secret if possible (dealer/3rd party)
	_, err = RecoverSecret(conf.suite, G, ked.K, ked.E, ked.D, conf.t, n)
	require.ErrorIs(test, err, ErrTooFewShares) // this test is supposed to fail
}

func TestPVSSBatch(test *testing.T) {
	n := uint32(5)
	t := 2*n/3 + 1
	conf := getConfig(n, t)
	G := conf.suite.Point().Base()

	// Shorthands to make code lighter
	suite := conf.suite
	H := conf.H
	X := conf.X
	x := conf.x

	// (1) Share distribution (multiple dealers)
	s0 := suite.Scalar().Pick(suite.RandomStream())
	e0, p0, err := EncShares(suite, H, X, s0, t)
	require.NoError(test, err)

	s1 := suite.Scalar().Pick(suite.RandomStream())
	e1, p1, err := EncShares(suite, H, X, s1, t)
	require.NoError(test, err)

	s2 := suite.Scalar().Pick(suite.RandomStream())
	e2, p2, err := EncShares(suite, H, X, s2, t)
	require.NoError(test, err)

	sH0 := make([]kyber.Point, n)
	sH1 := make([]kyber.Point, n)
	sH2 := make([]kyber.Point, n)
	for i := uint32(0); i < n; i++ {
		sH0[i] = p0.Eval(e0[i].S.I).V
		sH1[i] = p1.Eval(e1[i].S.I).V
		sH2[i] = p2.Eval(e2[i].S.I).V
	}

	// Batch verification
	X0, E0, err := VerifyEncShareBatch(suite, H, X, sH0, p0, e0)
	require.NoError(test, err)

	X1, E1, err := VerifyEncShareBatch(suite, H, X, sH1, p1, e1)
	require.NoError(test, err)

	X2, E2, err := VerifyEncShareBatch(suite, H, X, sH2, p2, e2)
	require.NoError(test, err)

	// Reorder (some) poly evals, keys, and shares
	P0 := []kyber.Point{p0.Eval(E0[0].S.I).V, p1.Eval(E1[0].S.I).V, p2.Eval(E2[0].S.I).V}
	P1 := []kyber.Point{p0.Eval(E0[1].S.I).V, p1.Eval(E1[1].S.I).V, p2.Eval(E2[1].S.I).V}
	P2 := []kyber.Point{p0.Eval(E0[2].S.I).V, p1.Eval(E1[2].S.I).V, p2.Eval(E2[2].S.I).V}
	P3 := []kyber.Point{p0.Eval(E0[3].S.I).V, p1.Eval(E1[3].S.I).V, p2.Eval(E2[3].S.I).V}

	Y0 := []kyber.Point{X0[0], X1[0], X2[0]}
	Y1 := []kyber.Point{X0[1], X1[1], X2[1]}
	Y2 := []kyber.Point{X0[2], X1[2], X2[2]}
	Y3 := []kyber.Point{X0[3], X1[3], X2[3]}

	Z0 := []*PubVerShare{E0[0], E1[0], E2[0]}
	Z1 := []*PubVerShare{E0[1], E1[1], E2[1]}
	Z2 := []*PubVerShare{E0[2], E1[2], E2[2]}
	Z3 := []*PubVerShare{E0[3], E1[3], E2[3]}

	globalChallenges := make([]kyber.Scalar, 3)
	globalChallenges[0], err = computeGlobalChallenge(suite, n, p0, e0)
	require.NoError(test, err)
	globalChallenges[1], err = computeGlobalChallenge(suite, n, p1, e1)
	require.NoError(test, err)
	globalChallenges[2], err = computeGlobalChallenge(suite, n, p2, e2)
	require.NoError(test, err)

	// (2) Share batch decryption (trustees)
	KD0, ED0, DD0, err := DecShareBatch(suite, H, Y0, P0, x[0], globalChallenges, Z0)
	require.NoError(test, err)

	KD1, ED1, DD1, err := DecShareBatch(suite, H, Y1, P1, x[1], globalChallenges, Z1)
	require.NoError(test, err)

	KD2, ED2, DD2, err := DecShareBatch(suite, H, Y2, P2, x[2], globalChallenges, Z2)
	require.NoError(test, err)

	KD3, ED3, DD3, err := DecShareBatch(suite, H, Y3, P3, x[3], globalChallenges, Z3)
	require.NoError(test, err)

	// Re-establish order
	XF0 := []kyber.Point{KD0[0], KD1[0], KD2[0], KD3[0]}
	XF1 := []kyber.Point{KD0[1], KD1[1], KD2[1], KD3[1]}
	XF2 := []kyber.Point{KD0[2], KD1[2], KD2[2], KD3[2]}

	EF0 := []*PubVerShare{ED0[0], ED1[0], ED2[0], ED3[0]}
	EF1 := []*PubVerShare{ED0[1], ED1[1], ED2[1], ED3[1]}
	EF2 := []*PubVerShare{ED0[2], ED1[2], ED2[2], ED3[2]}

	DF0 := []*PubVerShare{DD0[0], DD1[0], DD2[0], DD3[0]}
	DF1 := []*PubVerShare{DD0[1], DD1[1], DD2[1], DD3[1]}
	DF2 := []*PubVerShare{DD0[2], DD1[2], DD2[2], DD3[2]}

	// (3) Recover secrets
	S0, err := RecoverSecret(suite, G, XF0, EF0, DF0, t, n)
	require.NoError(test, err)

	S1, err := RecoverSecret(suite, G, XF1, EF1, DF1, t, n)
	require.NoError(test, err)

	S2, err := RecoverSecret(suite, G, XF2, EF2, DF2, t, n)
	require.NoError(test, err)

	// Verify secrets
	require.True(test, suite.Point().Mul(s0, nil).Equal(S0))
	require.True(test, suite.Point().Mul(s1, nil).Equal(S1))
	require.True(test, suite.Point().Mul(s2, nil).Equal(S2))
}
