package shuffle

import (
	"crypto/cipher"
	"errors"
	"github.com/dedis/crypto/abstract"
	"github.com/dedis/crypto/proof"
)

// XX the Zs in front of some field names are a kludge to make them
// accessible via the reflection API,
// which refuses to touch unexported fields in a struct.

// P (Prover) step 0: public inputs to the simple k-shuffle.
type ssa0 struct {
	X []abstract.Point
	Y []abstract.Point
}

// V (Verifier) step 1: random challenge t
type ssa1 struct {
	Zt abstract.Scalar
}

// P step 2: Theta vectors
type ssa2 struct {
	Theta []abstract.Point
}

// V step 3: random challenge c
type ssa3 struct {
	Zc abstract.Scalar
}

// P step 4: alpha vector
type ssa4 struct {
	Zalpha []abstract.Scalar
}

type SimpleShuffle struct {
	ste abstract.Suite
	p0  ssa0
	v1  ssa1
	p2  ssa2
	v3  ssa3
	p4  ssa4
}

// Simple helper to compute G^{ab-cd} for Theta vector computation.
func thenc(ste abstract.Suite, G abstract.Point,
	a, b, c, d abstract.Scalar) abstract.Point {

	var ab, cd abstract.Scalar
	if !a.Nil() {
		ab = ste.Scalar().Mul(a, b)
	} else {
		ab = ste.Scalar().Zero()
	}
	if !c.Nil() {
		if !d.Nil() {
			cd = ste.Scalar().Mul(c, d)
		} else {
			cd = c
		}
	} else {
		cd = ste.Scalar().Zero()
	}
	return ste.Point().Mul(G, ab.Sub(ab, cd))
}

func (ss *SimpleShuffle) Init(ste abstract.Suite, k int) *SimpleShuffle {
	ss.ste = ste
	ss.p0.X = make([]abstract.Point, k)
	ss.p0.Y = make([]abstract.Point, k)
	ss.p2.Theta = make([]abstract.Point, 2*k)
	ss.p4.Zalpha = make([]abstract.Scalar, 2*k-1)
	return ss
}

// The "Simple k-shuffle" defined in section 3 of
// Neff, "Verifiable Mixing (Shuffling) of ElGamal Pairs", 2004.
// The Scalar vector y must be a permutation of Scalar vector x
// but with all elements multiplied by common Scalar gamma.
func (ss *SimpleShuffle) Prove(G abstract.Point, gamma abstract.Scalar,
	x, y []abstract.Scalar, rand cipher.Stream,
	ctx proof.ProverContext) error {

	ste := ss.ste

	k := len(x)
	if k <= 1 {
		panic("can't shuffle length 1 vector")
	}
	if k != len(y) {
		panic("mismatched vector lengths")
	}

	//	// Dump input vectors to show their correspondences
	//	for i := 0; i < k; i++ {
	//		println("x",ste.Scalar().Mul(gamma,x[i]).String())
	//	}
	//	for i := 0; i < k; i++ {
	//		println("y",y[i].String())
	//	}

	// Step 0: inputs
	for i := 0; i < k; i++ { // (4)
		ss.p0.X[i] = ste.Point().Mul(G, x[i])
		ss.p0.Y[i] = ste.Point().Mul(G, y[i])
	}
	if err := ctx.Put(ss.p0); err != nil {
		return err
	}

	// V step 1
	if err := ctx.PubRand(&ss.v1); err != nil {
		return err
	}
	t := ss.v1.Zt

	// P step 2
	gamma_t := ste.Scalar().Mul(gamma, t)
	xhat := make([]abstract.Scalar, k)
	yhat := make([]abstract.Scalar, k)
	for i := 0; i < k; i++ { // (5) and (6) xhat,yhat vectors
		xhat[i] = ste.Scalar().Sub(x[i], t)
		yhat[i] = ste.Scalar().Sub(y[i], gamma_t)
	}
	thlen := 2*k - 1 // (7) theta and Theta vectors
	theta := make([]abstract.Scalar, thlen)
	ctx.PriRand(theta)
	Theta := make([]abstract.Point, thlen+1)
	nilScalar := abstract.Scalar{nil}
	Theta[0] = thenc(ste, G, nilScalar, nilScalar, theta[0], yhat[0])
	for i := 1; i < k; i++ {
		Theta[i] = thenc(ste, G, theta[i-1], xhat[i],
			theta[i], yhat[i])
	}
	for i := k; i < thlen; i++ {
		Theta[i] = thenc(ste, G, theta[i-1], gamma,
			theta[i], nilScalar)
	}
	Theta[thlen] = thenc(ste, G, theta[thlen-1], gamma,
		nilScalar, nilScalar)
	ss.p2.Theta = Theta
	if err := ctx.Put(ss.p2); err != nil {
		return err
	}

	// V step 3
	if err := ctx.PubRand(&ss.v3); err != nil {
		return err
	}
	c := ss.v3.Zc

	// P step 4
	alpha := make([]abstract.Scalar, thlen)
	runprod := ste.Scalar().Set(c)
	for i := 0; i < k; i++ { // (8)
		runprod.Mul(runprod, xhat[i])
		runprod.Div(runprod, yhat[i])
		alpha[i] = ste.Scalar().Add(theta[i], runprod)
	}
	gammainv := ste.Scalar().Inv(gamma)
	rungamma := ste.Scalar().Set(c)
	for i := 1; i < k; i++ {
		rungamma.Mul(rungamma, gammainv)
		alpha[thlen-i] = ste.Scalar().Add(theta[thlen-i], rungamma)
	}
	ss.p4.Zalpha = alpha
	if err := ctx.Put(ss.p4); err != nil {
		return err
	}

	return nil
}

// Simple helper to verify Theta elements,
// by checking whether A^a*B^-b = T.
// P,Q,s are simply "scratch" abstract.Point/Scalars reused for efficiency.
func thver(A, B, T, P, Q abstract.Point, a, b, s abstract.Scalar) bool {
	P.Mul(A, a)
	Q.Mul(B, s.Neg(b))
	P.Add(P, Q)
	return P.Equal(T)
}

// Verifier for Neff simple k-shuffle proofs.
func (ss *SimpleShuffle) Verify(G, Gamma abstract.Point,
	ctx proof.VerifierContext) error {

	ste := ss.ste

	// extract proof transcript
	X := ss.p0.X
	Y := ss.p0.Y
	Theta := ss.p2.Theta
	alpha := ss.p4.Zalpha

	// Validate all vector lengths
	k := len(Y)
	thlen := 2*k - 1
	if k <= 1 || len(Y) != k || len(Theta) != thlen+1 ||
		len(alpha) != thlen {
		return errors.New("malformed SimpleShuffleProof")
	}

	// check verifiable challenges (usually by reproducing a hash)
	if err := ctx.Get(ss.p0); err != nil {
		return err
	}
	if err := ctx.PubRand(&ss.v1); err != nil { // fills in v1
		return err
	}
	t := ss.v1.Zt
	if err := ctx.Get(ss.p2); err != nil {
		return err
	}
	if err := ctx.PubRand(&ss.v3); err != nil { // fills in v3
		return err
	}
	c := ss.v3.Zc
	if err := ctx.Get(ss.p4); err != nil {
		return err
	}

	// Verifier step 5
	negt := ste.Scalar().Neg(t)
	U := ste.Point().Mul(G, negt)
	W := ste.Point().Mul(Gamma, negt)
	Xhat := make([]abstract.Point, k)
	Yhat := make([]abstract.Point, k)
	for i := 0; i < k; i++ {
		Xhat[i] = ste.Point().Add(X[i], U)
		Yhat[i] = ste.Point().Add(Y[i], W)
	}
	P := ste.Point() // scratch variables
	Q := ste.Point()
	s := ste.Scalar()
	good := true
	good = good && thver(Xhat[0], Yhat[0], Theta[0], P, Q, c, alpha[0], s)
	for i := 1; i < k; i++ {
		good = good && thver(Xhat[i], Yhat[i], Theta[i], P, Q,
			alpha[i-1], alpha[i], s)
	}
	for i := k; i < thlen; i++ {
		good = good && thver(Gamma, G, Theta[i], P, Q,
			alpha[i-1], alpha[i], s)
	}
	good = good && thver(Gamma, G, Theta[thlen], P, Q,
		alpha[thlen-1], c, s)
	if !good {
		return errors.New("incorrect SimpleShuffleProof")
	}

	return nil
}
