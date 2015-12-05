// Package shuffle implements Andrew Neff's verifiable shuffle proof scheme.
// Neff's shuffle proof algorithm as implemented here is described in the paper
// "Verifiable Mixing (Shuffling) of ElGamal Pairs", April 2004.
//
// The PairShuffle type implements the general algorithm
// to prove the correctness of a shuffle of arbitrary ElGamal pairs.
// This will be the primary API of interest for most applications.
// For basic usage, the caller should first instantiate a PairShuffle object,
// then invoke PairShuffle.Init() to initialize the shuffle parameters,
// and finally invoke PairShuffle.Shuffle() to shuffle
// a list of ElGamal pairs, yielding a list of re-randomized pairs
// and a noninteractive proof of its correctness.
//
// The SimpleShuffle type implements Neff's more restrictive "simple shuffle",
// which requires the prover to know the discrete logarithms
// of all the individual ElGamal ciphertexts involved in the shuffle.
// The general PairShuffle builds on this SimpleShuffle scheme,
// but SimpleShuffle may also be used by itself in situations
// that satisfy its assumptions, and is more efficient.
package shuffle

import (
	"crypto/cipher"
	"errors"
	"github.com/dedis/crypto/abstract"
	"github.com/dedis/crypto/proof"
	"github.com/dedis/crypto/random"
)

// XX these could all be inlined into PairShuffleProof; do we want to?

// XX the Zs in front of some field names are a kludge to make them
// accessible via the reflection API,
// which refuses to touch unexported fields in a struct.

// P (Prover) step 1: public commitments
type ega1 struct {
	Gamma            abstract.Point
	A, C, U, W       []abstract.Point
	Lambda1, Lambda2 abstract.Point
}

// V (Verifier) step 2: random challenge t
type ega2 struct {
	Zrho []abstract.Scalar
}

// P step 3: Theta vectors
type ega3 struct {
	D []abstract.Point
}

// V step 4: random challenge c
type ega4 struct {
	Zlambda abstract.Scalar
}

// P step 5: alpha vector
type ega5 struct {
	Zsigma []abstract.Scalar
	Ztau   abstract.Scalar
}

// P and V, step 5: simple k-shuffle proof
type ega6 struct {
	SimpleShuffle
}

// PairShuffle creates a proof of the correctness of a shuffle
// of a series of ElGamal pairs.
//
// The caller must first invoke Init()
// to establish the cryptographic parameters for the shuffle:
// in particular, the relevant cryptographic Group,
// and the number of ElGamal pairs to be shuffled.
//
// The caller then may either perform its own shuffle,
// according to a permutation of the caller's choosing,
// and invoke Prove() to create a proof of its correctness;
// or alternatively the caller may simply invoke Shuffle()
// to pick a random permutation, compute the shuffle,
// and compute the correctness proof.
type PairShuffle struct {
	ste abstract.Suite
	k   int
	p1  ega1
	v2  ega2
	p3  ega3
	v4  ega4
	p5  ega5
	pv6 SimpleShuffle
}

// Create a new PairShuffleProof instance for a k-element ElGamal pair shuffle.
// This protocol follows the ElGamal Pair Shuffle defined in section 4 of
// Andrew Neff, "Verifiable Mixing (Shuffling) of ElGamal Pairs", 2004.
func (ps *PairShuffle) Init(ste abstract.Suite, k int) *PairShuffle {

	if k <= 1 {
		panic("can't shuffle permutation of size <= 1")
	}

	// Create a well-formed PairShuffleProof with arrays correctly sized.
	ps.ste = ste
	ps.k = k
	ps.p1.A = make([]abstract.Point, k)
	ps.p1.C = make([]abstract.Point, k)
	ps.p1.U = make([]abstract.Point, k)
	ps.p1.W = make([]abstract.Point, k)
	ps.v2.Zrho = make([]abstract.Scalar, k)
	ps.p3.D = make([]abstract.Point, k)
	ps.p5.Zsigma = make([]abstract.Scalar, k)
	ps.pv6.Init(ste, k)

	return ps
}

func (ps *PairShuffle) Prove(
	pi []int, g, h abstract.Point, beta []abstract.Scalar,
	X, Y []abstract.Point, rand cipher.Stream,
	ctx proof.ProverContext) error {

	ste := ps.ste
	k := ps.k
	if k != len(pi) || k != len(beta) {
		panic("mismatched vector lengths")
	}

	// Compute pi^-1 inverse permutation
	piinv := make([]int, k)
	for i := 0; i < k; i++ {
		piinv[pi[i]] = i
	}

	// P step 1
	p1 := &ps.p1
	z := ste.Scalar() // scratch

	// pick random secrets
	u := make([]abstract.Scalar, k)
	w := make([]abstract.Scalar, k)
	a := make([]abstract.Scalar, k)
	var tau0, nu, gamma abstract.Scalar
	ctx.PriRand(u, w, a, &tau0, &nu, &gamma)

	// compute public commits
	p1.Gamma = ste.Point().Mul(g, gamma)
	wbeta := ste.Scalar() // scratch
	wbetasum := ste.Scalar().Set(tau0)
	p1.Lambda1 = ste.Point().Null()
	p1.Lambda2 = ste.Point().Null()
	XY := ste.Point()  // scratch
	wu := ste.Scalar() // scratch
	for i := 0; i < k; i++ {
		p1.A[i] = ste.Point().Mul(g, a[i])
		p1.C[i] = ste.Point().Mul(g, z.Mul(gamma, a[pi[i]]))
		p1.U[i] = ste.Point().Mul(g, u[i])
		p1.W[i] = ste.Point().Mul(g, z.Mul(gamma, w[i]))
		wbetasum.Add(wbetasum, wbeta.Mul(w[i], beta[pi[i]]))
		p1.Lambda1.Add(p1.Lambda1, XY.Mul(X[i],
			wu.Sub(w[piinv[i]], u[i])))
		p1.Lambda2.Add(p1.Lambda2, XY.Mul(Y[i],
			wu.Sub(w[piinv[i]], u[i])))
	}
	p1.Lambda1.Add(p1.Lambda1, XY.Mul(g, wbetasum))
	p1.Lambda2.Add(p1.Lambda2, XY.Mul(h, wbetasum))
	if err := ctx.Put(p1); err != nil {
		return err
	}

	// V step 2
	v2 := &ps.v2
	if err := ctx.PubRand(v2); err != nil {
		return err
	}
	B := make([]abstract.Point, k)
	for i := 0; i < k; i++ {
		P := ste.Point().Mul(g, v2.Zrho[i])
		B[i] = P.Sub(P, p1.U[i])
	}

	// P step 3
	p3 := &ps.p3
	b := make([]abstract.Scalar, k)
	for i := 0; i < k; i++ {
		b[i] = ste.Scalar().Sub(v2.Zrho[i], u[i])
	}
	d := make([]abstract.Scalar, k)
	for i := 0; i < k; i++ {
		d[i] = ste.Scalar().Mul(gamma, b[pi[i]])
		p3.D[i] = ste.Point().Mul(g, d[i])
	}
	if err := ctx.Put(p3); err != nil {
		return err
	}

	// V step 4
	v4 := &ps.v4
	if err := ctx.PubRand(v4); err != nil {
		return err
	}

	// P step 5
	p5 := &ps.p5
	r := make([]abstract.Scalar, k)
	for i := 0; i < k; i++ {
		r[i] = ste.Scalar().Add(a[i], z.Mul(v4.Zlambda, b[i]))
	}
	s := make([]abstract.Scalar, k)
	for i := 0; i < k; i++ {
		s[i] = ste.Scalar().Mul(gamma, r[pi[i]])
	}
	p5.Ztau = ste.Scalar().Neg(tau0)
	for i := 0; i < k; i++ {
		p5.Zsigma[i] = ste.Scalar().Add(w[i], b[pi[i]])
		p5.Ztau.Add(p5.Ztau, z.Mul(b[i], beta[i]))
	}
	if err := ctx.Put(p5); err != nil {
		return err
	}

	// P,V step 6: embedded simple k-shuffle proof
	return ps.pv6.Prove(g, gamma, r, s, rand, ctx)
}

// Verifier for ElGamal Pair Shuffle proofs.
func (ps *PairShuffle) Verify(
	g, h abstract.Point, X, Y, Xbar, Ybar []abstract.Point,
	ctx proof.VerifierContext) error {

	// Validate all vector lengths
	ste := ps.ste
	k := ps.k
	if len(X) != k || len(Y) != k || len(Xbar) != k || len(Ybar) != k {
		panic("mismatched vector lengths")
	}

	// P step 1
	p1 := &ps.p1
	if err := ctx.Get(p1); err != nil {
		return err
	}

	// V step 2
	v2 := &ps.v2
	if err := ctx.PubRand(v2); err != nil {
		return err
	}
	B := make([]abstract.Point, k)
	for i := 0; i < k; i++ {
		P := ste.Point().Mul(g, v2.Zrho[i])
		B[i] = P.Sub(P, p1.U[i])
	}

	// P step 3
	p3 := &ps.p3
	if err := ctx.Get(p3); err != nil {
		return err
	}

	// V step 4
	v4 := &ps.v4
	if err := ctx.PubRand(v4); err != nil {
		return err
	}

	// P step 5
	p5 := &ps.p5
	if err := ctx.Get(p5); err != nil {
		return err
	}

	// P,V step 6: simple k-shuffle
	if err := ps.pv6.Verify(g, p1.Gamma, ctx); err != nil {
		return err
	}

	// V step 7
	Phi1 := ste.Point().Null()
	Phi2 := ste.Point().Null()
	P := ste.Point() // scratch
	Q := ste.Point() // scratch
	for i := 0; i < k; i++ {
		Phi1 = Phi1.Add(Phi1, P.Mul(Xbar[i], p5.Zsigma[i])) // (31)
		Phi1 = Phi1.Sub(Phi1, P.Mul(X[i], v2.Zrho[i]))
		Phi2 = Phi2.Add(Phi2, P.Mul(Ybar[i], p5.Zsigma[i])) // (32)
		Phi2 = Phi2.Sub(Phi2, P.Mul(Y[i], v2.Zrho[i]))
		//		println("i",i)
		if !P.Mul(p1.Gamma, p5.Zsigma[i]).Equal( // (33)
			Q.Add(p1.W[i], p3.D[i])) {
			return errors.New("invalid PairShuffleProof")
		}
	}
	//	println("last")
	//	println("Phi1",Phi1.String());
	//	println("Phi2",Phi2.String());
	//	println("1",P.Add(p1.Lambda1,Q.Mul(g,p5.Ztau)).String());
	//	println("2",P.Add(p1.Lambda2,Q.Mul(h,p5.Ztau)).String());
	if !P.Add(p1.Lambda1, Q.Mul(g, p5.Ztau)).Equal(Phi1) || // (34)
		!P.Add(p1.Lambda2, Q.Mul(h, p5.Ztau)).Equal(Phi2) { // (35)
		return errors.New("invalid PairShuffleProof")
	}

	return nil
}

// Randomly shuffle and re-randomize a set of ElGamal pairs,
// producing a correctness proof in the process.
// Returns (Xbar,Ybar), the shuffled and randomized pairs.
// If g or h is nil, the standard base point is used.
func Shuffle(suite abstract.Suite, g, h abstract.Point, X, Y []abstract.Point,
	rand cipher.Stream) (XX, YY []abstract.Point, P proof.Prover) {

	k := len(X)
	if k != len(Y) {
		panic("X,Y vectors have inconsistent length")
	}

	ps := PairShuffle{}
	ps.Init(suite, k)

	// Pick a random permutation
	pi := make([]int, k)
	for i := 0; i < k; i++ { // Initialize a trivial permutation
		pi[i] = i
	}
	for i := k - 1; i > 0; i-- { // Shuffle by random swaps
		j := int(random.Uint64(rand) % uint64(i+1))
		if j != i {
			t := pi[j]
			pi[j] = pi[i]
			pi[i] = t
		}
	}

	// Pick a fresh ElGamal blinding factor for each pair
	beta := make([]abstract.Scalar, k)
	for i := 0; i < k; i++ {
		beta[i] = ps.ste.Scalar().Random(rand)
	}

	// Create the output pair vectors
	Xbar := make([]abstract.Point, k)
	Ybar := make([]abstract.Point, k)
	for i := 0; i < k; i++ {
		Xbar[i] = ps.ste.Point().Mul(g, beta[pi[i]])
		Xbar[i].Add(Xbar[i], X[pi[i]])
		Ybar[i] = ps.ste.Point().Mul(h, beta[pi[i]])
		Ybar[i].Add(Ybar[i], Y[pi[i]])
	}

	prover := func(ctx proof.ProverContext) error {
		return ps.Prove(pi, g, h, beta, X, Y, rand, ctx)
	}
	return Xbar, Ybar, prover
}

// Produce a Sigma-protocol verifier to check the correctness of a shuffle.
func Verifier(suite abstract.Suite, g, h abstract.Point,
	X, Y, Xbar, Ybar []abstract.Point) proof.Verifier {

	ps := PairShuffle{}
	ps.Init(suite, len(X))
	verifier := func(ctx proof.VerifierContext) error {
		return ps.Verify(g, h, X, Y, Xbar, Ybar, ctx)
	}
	return verifier
}
