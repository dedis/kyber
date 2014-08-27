package shuffle

import (
	"errors"
	"crypto/cipher"
	"dissent/crypto"
)


// P (Prover) step 0: public inputs to the simple k-shuffle.
type ssa0 struct {
	X []crypto.Point
	Y []crypto.Point
}

// V (Verifier) step 1: random challenge t
type ssa1 struct {
	t crypto.Secret
}

// P step 2: Theta vectors
type ssa2 struct {
	Theta []crypto.Point
}

// V step 3: random challenge c
type ssa3 struct {
	c crypto.Secret
}

// P step 4: alpha vector
type ssa4 struct {
	alpha []crypto.Secret
}

type SimpleShuffle struct {
	grp crypto.Group
	p0 ssa0
	v1 ssa1
	p2 ssa2
	v3 ssa3
	p4 ssa4
}

// Simple helper to compute G^{ab-cd} for Theta vector computation
func thenc(grp crypto.Group, G crypto.Point,
		a,b,c,d crypto.Secret) crypto.Point {

	var ab,cd crypto.Secret
	if a != nil {
		ab = grp.Secret().Mul(a,b)
	} else {
		ab = grp.Secret().Zero()
	}
	if c != nil {
		if d != nil {
			cd = grp.Secret().Mul(c,d)
		} else {
			cd = c
		}
	} else {
		cd = grp.Secret().Zero()
	}
	return grp.Point().Mul(G,ab.Sub(ab,cd))
}

func (ss *SimpleShuffle) Init(grp crypto.Group, k int) *SimpleShuffle {
	ss.grp = grp
	ss.p0.X = make([]crypto.Point, k)
	ss.p0.Y = make([]crypto.Point, k)
	ss.p2.Theta = make([]crypto.Point, 2*k)
	ss.p4.alpha = make([]crypto.Secret, 2*k-1)
	return ss
}

// The "Simple k-shuffle" defined in section 3 of
// Neff, "Verifiable Mixing (Shuffling) of ElGamal Pairs", 2004.
// The Secret vector y must be a permutation of Secret vector x
// but with all elements multiplied by common Secret gamma.
func (ss *SimpleShuffle) Prove(G crypto.Point, gamma crypto.Secret,
			x,y []crypto.Secret, rand cipher.Stream,
			ctx Context) {

	grp := ss.grp

	k := len(x)
	if k <= 1 {
		panic("can't shuffle length 1 vector")
	}
	if k != len(y) {
		panic("mismatched vector lengths")
	}

	// Use non-interactive verifier by default, but can be overridden
//	if v == nil {
//		v = niVerifier
//	}

	// Step 0: inputs
	for i := 0; i < k; i++ {	// (4)
		ss.p0.X[i] = grp.Point().Mul(G,x[i])
		ss.p0.Y[i] = grp.Point().Mul(G,y[i])
	}
	ctx.Put(ss.p0)

	// V step 1
	ctx.Get(ss.v1)
	t := ss.v1.t

	// P step 2
	gamma_t := grp.Secret().Mul(gamma,t)
	xhat := make([]crypto.Secret, k)
	yhat := make([]crypto.Secret, k)
	for i := 0; i < k; i++ {	// (5) and (6) xhat,yhat vectors
		xhat[i] = grp.Secret().Sub(x[i], t)
		yhat[i] = grp.Secret().Sub(x[i], gamma_t)
	}
	thlen := 2*k-1			// (7) theta and Theta vectors
	theta := make([]crypto.Secret, thlen)
	Theta := make([]crypto.Point, thlen+1)
	for i := 0; i < thlen; i++ {
		theta[i] = grp.Secret().Pick(rand)
	}
	Theta[0] = thenc(grp, G, nil, nil, theta[0], yhat[0])
	for i := 1; i < k; i++ {
		Theta[i] = thenc(grp, G, theta[i-1], xhat[i],
					theta[i], yhat[i])
	}
	for i := k; i < thlen; i++ {
		Theta[i] = thenc(grp, G, theta[i-1], gamma,
					theta[i], nil)
	}
	Theta[thlen] = thenc(grp, G, theta[thlen-1], gamma, nil, nil)
	ss.p2.Theta = Theta
	ctx.Put(ss.p2)

	// V step 3
	ctx.Get(ss.v3)
	c := ss.v3.c

	// P step 4
	alpha := make([]crypto.Secret, thlen)
	runprod := grp.Secret().Set(c)
	for i := 0; i < k; i++ {		// (8)
		runprod.Mul(runprod,xhat[i])
		runprod.Div(runprod,yhat[i])
		alpha[i] = grp.Secret().Add(theta[i],runprod)
	}
	gammainv := grp.Secret().Inv(gamma)
	rungamma := grp.Secret().Set(c)
	for i := 1; i < k; i++ {
		rungamma.Mul(rungamma,gammainv)
		alpha[thlen-i] = grp.Secret().Add(theta[thlen-i],rungamma)
	}
	ss.p4.alpha = alpha
	ctx.Put(ss.p4)
}

// Simple helper to verify Theta elements,
// by checking whether A^a*B^-b = T.
// P,Q,s are simply "scratch" crypto.Point/Secrets reused for efficiency.
func thver(A,B,T,P,Q crypto.Point, a,b,s crypto.Secret) bool {
	P.Mul(A,a)
	Q.Mul(B,s.Neg(b))
	P.Add(P,Q)
	return P.Equal(T)
}

// Verifier for Neff simple k-shuffle proofs.
func (ss *SimpleShuffle) Verify(G, Gamma crypto.Point,
			ctx Context) error {

	grp := ss.grp

	// extract proof transcript
	X := ss.p0.X
	Y := ss.p0.Y
	t := ss.v1.t
	Theta := ss.p2.Theta
	c := ss.v3.c
	alpha := ss.p4.alpha

	// Validate all vector lengths
	k := len(Y)
	thlen := 2*k-1
	if k <= 1 || len(Y) != k || len(Theta) != thlen+1 ||
			len(alpha) != thlen {
		return errors.New("malformed SimpleShuffleProof")
	}

	// check verifiable challenges (usually by reproducing a hash)
	ctx.Put(ss.p0)
	var checkv1 ssa1
	ctx.Get(checkv1)		// fills in v1
	ctx.Put(ss.p2)
	var checkv3 ssa3
	ctx.Get(checkv3)		// fills in v3
	ctx.Put(ss.p4)
	if !ss.v1.t.Equal(checkv1.t) || !ss.v3.c.Equal(checkv3.c) {
		return errors.New("incorrect challenges in SimpleShuffleProof")
	}

	// Verifier step 5
	negt := grp.Secret().Neg(t)
	U := grp.Point().Mul(G,negt)
	W := grp.Point().Mul(Gamma,negt)
	Xhat := make([]crypto.Point,k)
	Yhat := make([]crypto.Point,k)
	for i := 0; i < k; i++ {
		Xhat[i] = grp.Point().Add(X[i],U)
		Yhat[i] = grp.Point().Add(Y[i],W)
	}
	P := grp.Point()	// scratch variables
	Q := grp.Point()
	s := grp.Secret()
	good := true
	good = good && thver(Xhat[0],Yhat[0],Theta[0],P,Q,c,alpha[0],s)
	for i := 1; i < k; i++ {
		good = good && thver(Xhat[i],Yhat[i],Theta[i],P,Q,
					alpha[i-1],alpha[i],s)
	}
	for i := k; i < thlen; i++ {
		good = good && thver(Gamma,G,Theta[i],P,Q,
					alpha[i-1],alpha[i],s)
	}
	good = good && thver(Gamma,G,Theta[thlen],P,Q,
					alpha[thlen-1],c,s)
	if !good {
		return errors.New("incorrect SimpleShuffleProof")
	}

	return nil
}

