package proto

import (
	"errors"
	"crypto/cipher"
	"dissent/crypto"
)


// XX these could all be inlined into PairShuffleProof; do we want to?

// P (Prover) step 1: public commitments
type ega1 struct {
	Gamma crypto.Point
	A,C,U,W []crypto.Point
	Lambda1,Lambda2 crypto.Point
}

// V (Verifier) step 2: random challenge t
type ega2 struct {
	rho []crypto.Secret
}

// P step 3: Theta vectors
type ega3 struct {
	D []crypto.Point
}

// V step 4: random challenge c
type ega4 struct {
	lambda crypto.Secret
}

// P step 5: alpha vector
type ega5 struct {
	sigma []crypto.Secret
	tau crypto.Secret
}

// P and V, step 5: simple k-shuffle proof
type ega6 struct {
	SimpleShuffleProof
}


type PairShuffleProof struct {
	grp crypto.Group
	k int
	p1 ega1
	v2 ega2
	p3 ega3
	v4 ega4
	p5 ega5
	pv6 *SimpleShuffleProof
}

// Create a new PairShuffleProof instance for a k-element ElGamal pair shuffle.
// This protocol follows the ElGamal Pair Shuffle defined in section 4 of
// Andrew Neff, "Verifiable Mixing (Shuffling) of ElGamal Pairs", 2004.
func NewPairShuffleProof(grp crypto.Group, k int) *PairShuffleProof {

	if k <= 1 {
		panic("can't shuffle permutation of size <= 1")
	}

	// Create a well-formed PairShuffleProof with arrays correctly sized.
	var prf PairShuffleProof
	prf.grp = grp
	prf.k = k
	prf.p1.A = make([]crypto.Point, k)
	prf.p1.C = make([]crypto.Point, k)
	prf.p1.U = make([]crypto.Point, k)
	prf.p1.W = make([]crypto.Point, k)
	prf.v2.rho = make([]crypto.Secret, k)
	prf.p3.D = make([]crypto.Point, k)
	prf.p5.sigma = make([]crypto.Secret, k)
	prf.pv6 = NewSimpleShuffleProof(k)

	return &prf
}

func (prf *PairShuffleProof) Prove(
		pi []int, g,h crypto.Point, beta []crypto.Secret,
		X,Y []crypto.Point, ctx Context) {

	grp := prf.grp
	k := prf.k
	if k != len(pi) || k != len(beta) {
		panic("mismatched vector lengths")
	}

	// Compute pi^-1 inverse permutation
	piinv := make([]int, k)
	for i := 0; i < k; i++ {
		piinv[pi[i]] = i
	}

	// P step 1
	p1 := &prf.p1
	z := grp.Secret()	// scratch

	// pick random secrets
	u := make([]crypto.Secret, k);
	w := make([]crypto.Secret, k);
	a := make([]crypto.Secret, k);
	var tau0,nu,gamma crypto.Secret
	ctx.PriRand(u,w,a,&tau0,&nu,&gamma)

	// compute public commits
	p1.Gamma := grp.Point().Encrypt(g,gamma)
	wbeta := grp.Secret()		// scratch
	wbetasum := grp.Secret().Set(tau0)
	p1.Lambda1 := grp.Point().Null()
	p1.Lambda2 := grp.Point().Null()
	XY := grp.Point()		// scratch
	wu := grp.Secret()		// scratch
	for i := 0; i < k; i++ {
		p1.A[i] = grp.Point().Encrypt(g,a[i])
		p1.C[i] = grp.Point().Encrypt(g,z.Mul(gamma,a[pi[i]]))
		p1.U[i] = grp.Point().Encrypt(g,u[i])
		p1.W[i] = grp.Point().Encrypt(g,z.Mul(gamma,w[i]))
		wbetasum.Add(wbetasum,wbeta.Mul(w[i],beta[pi[i]]))
		p1.Lambda1.Add(p1.Lambda1,XY.Encrypt(X[i],
						wu.Sub(w[piinv[i]],u[i])))
		p1.Lambda2.Add(p1.Lambda2,XY.Encrypt(Y[i],
						wu.Sub(w[piinv[i]],u[i])))
	}
	p1.Lambda1.Add(XY.Encrypt(g,wbetasum))
	p1.Lambda2.Add(XY.Encrypt(h,wbetasum))
	ctx.Put(p1)

	// V step 2
	v2 := &prf.v2
	ctx.PubRand(v2)
	B := make([]crypto.Point, k)
	for i := 0; i < k; i++ {
		P := grp.Point().Encrypt(g,v2.rho[i])
		B[i] = P.Sub(P,p1.U[i])
	}

	// P step 3
	p3 := &prf.p3
	b := make([]crypto.Secret, k)
	for i := 0; i < k; i++ {
		b[i] = grp.Secret().Sub(v2.rho[i],u[i])
	}
	d := make([]crypto.Secret, k)
	for i := 0; i < k; i++ {
		d[i] = grp.Secret().Mul(gamma,b[pi[i]])
		p3.D[i] = grp.Point().Encrypt(g,d[i])
	}
	ctx.Put(p3)

	// V step 4
	v4 := &prf.v4
	ctx.PubRand(v4)

	// P step 5
	pt := &prf.p5
	r := make([]crypto.Secret, k)
	for i := 0; i < k; i++ {
		r[i] = grp.Secret().Add(a[i],z.Mul(v4.lambda,b[i]))
	}
	s := make([]crypto.Secret, k)
	for i := 0; i < k; i++ {
		s[i] = grp.Secret().Mul(gamma,r[pi[i]])
	}
	p5.tau = grp.Secret().Neg(tau0)
	for i := 0; i < k; i++ {
		p5.sigma[i] = grp.Secret().Add(w[i],b[pi[i]])
		p5.tau.Add(p5.tau,z.Mul(b[pi[i]],beta[pi[i]]))
	}
	ctx.Put(p5)

	// P,V step 6: embedded simple k-shuffle proof
	prf.pv6.Prove(grp, g, gamma, r, s, rand, v)
}


// Verifier for ElGamal Pair Shuffle proofs.
func (prf *PairShuffleProof) Verify(
		g,h crypto.Point, X,Y,Xbar,Ybar []crypto.Point,
		ctx Context) error {

	// Validate all vector lengths
	grp := prf.grp
	k := prf.k
	if len(X) != k || len(Y) != k || len(Xbar) != k || len(Ybar) != k {
		panic("mismatched vector lengths")
	}

	// P step 1
	p1 := &prf.p1
	ctx.Get(p1)

	// V step 2
	v2 := &prf.v2
	ctx.PubRand(v2)
	B := make([]crypto.Point, k)
	for i := 0; i < k; i++ {
		P := grp.Point().Encrypt(g,v2.rho[i])
		B[i] = P.Sub(P,p1.U[i])
	}

	// P step 3
	p3 := &prf.p3
	ctx.Get(p3)

	// V step 4
	v4 := &prf.v4
	ctx.PubRand(v4)

	// P step 5
	p5 := &prf.p5
	ctx.Get(p5)

	// P,V step 6: simple k-shuffle
	if err := prf.pv6.Verify(g,p1.Gamma,R,S,ctx); err != nil {
		return err
	}

	// V step 7
	Phi1 := grp.Point().Null()
	Phi2 := grp.Point().Null()
	P := grp.Point()		// scratch
	Q := grp.Point()		// scratch
	for i := 0; i < k; i++ {
		Phi1 = Phi1.Add(Phi1,P.Encrypt(Xbar[i],p5.sigma[i]))	// (31)
		Phi1 = Phi1.Sub(Phi1,P.Encrypt(X[i],v2.rho[i]))
		Phi2 = Phi2.Add(Phi2,P.Encrypt(Ybar[i],p5.sigma[i]))	// (32)
		Phi2 = Phi2.Sub(Phi2,P.Encrypt(Y[i],v2.rho[i]))
		if !Equal(P.Encrypt(p1.Gamma,p5.sigma[i]),		// (33)
			  Q.Add(p1.W[i],p3.D[i])) {
			return errors.New("invalid PairShuffleProof")
		}
	}
	if !Equal(P.Add(p1.Lambda1,Q.Encrypt(g,p5.tau)),Phi1) ||	// (34)
	   !Equal(P.Add(p1.Lambda2,Q.Encrypt(h,p5.tau)),Phi2) {		// (35)
		return errors.New("invalid PairShuffleProof")
	}

	return nil
}

