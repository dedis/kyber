package shuffle

import (
	"errors"
	"crypto/cipher"
	"dissent/crypto"
	"dissent/crypto/proof"
)


// XX the Zs in front of some field names are a kludge to make them
// accessible via the reflection API,
// which refuses to touch unexported fields in a struct.

// P (Prover) step 0: public inputs to the simple k-shuffle.
type ssa0 struct {
	X []crypto.Point
	Y []crypto.Point
}

// V (Verifier) step 1: random challenge t
type ssa1 struct {
	Zt crypto.Secret
}

// P step 2: Theta vectors
type ssa2 struct {
	Theta []crypto.Point
}

// V step 3: random challenge c
type ssa3 struct {
	Zc crypto.Secret
}

// P step 4: alpha vector
type ssa4 struct {
	Zalpha []crypto.Secret
}

type SimpleShuffle struct {
	grp crypto.Group
	p0 ssa0
	v1 ssa1
	p2 ssa2
	v3 ssa3
	p4 ssa4
}

// Simple helper to compute G^{ab-cd} for Theta vector computation.
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
	ss.p4.Zalpha = make([]crypto.Secret, 2*k-1)
	return ss
}

// The "Simple k-shuffle" defined in section 3 of
// Neff, "Verifiable Mixing (Shuffling) of ElGamal Pairs", 2004.
// The Secret vector y must be a permutation of Secret vector x
// but with all elements multiplied by common Secret gamma.
func (ss *SimpleShuffle) Prove(G crypto.Point, gamma crypto.Secret,
			x,y []crypto.Secret, rand cipher.Stream,
			ctx proof.ProverContext) error {

	grp := ss.grp

	k := len(x)
	if k <= 1 {
		panic("can't shuffle length 1 vector")
	}
	if k != len(y) {
		panic("mismatched vector lengths")
	}

//	// Dump input vectors to show their correspondences
//	for i := 0; i < k; i++ {
//		println("x",grp.Secret().Mul(gamma,x[i]).String())
//	}
//	for i := 0; i < k; i++ {
//		println("y",y[i].String())
//	}

	// Step 0: inputs
	for i := 0; i < k; i++ {	// (4)
		ss.p0.X[i] = grp.Point().Mul(G,x[i])
		ss.p0.Y[i] = grp.Point().Mul(G,y[i])
	}
	if err := ctx.Put(ss.p0); err != nil {
		return err
	}

	// V step 1
	ctx.PubRand(&ss.v1)
	t := ss.v1.Zt

	// P step 2
	gamma_t := grp.Secret().Mul(gamma,t)
	xhat := make([]crypto.Secret, k)
	yhat := make([]crypto.Secret, k)
	for i := 0; i < k; i++ {	// (5) and (6) xhat,yhat vectors
		xhat[i] = grp.Secret().Sub(x[i], t)
		yhat[i] = grp.Secret().Sub(y[i], gamma_t)
	}
	thlen := 2*k-1			// (7) theta and Theta vectors
	theta := make([]crypto.Secret, thlen)
	ctx.PriRand(theta)
	Theta := make([]crypto.Point, thlen+1)
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
	if err := ctx.Put(ss.p2); err != nil {
		return err
	}

	// V step 3
	ctx.PubRand(&ss.v3)
	c := ss.v3.Zc

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
	ss.p4.Zalpha = alpha
	if err := ctx.Put(ss.p4); err != nil {
		return err
	}

	return nil
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
			ctx proof.VerifierContext) error {

	grp := ss.grp

	// extract proof transcript
	X := ss.p0.X
	Y := ss.p0.Y
	t := ss.v1.Zt
	Theta := ss.p2.Theta
	c := ss.v3.Zc
	alpha := ss.p4.Zalpha

	// Validate all vector lengths
	k := len(Y)
	thlen := 2*k-1
	if k <= 1 || len(Y) != k || len(Theta) != thlen+1 ||
			len(alpha) != thlen {
		return errors.New("malformed SimpleShuffleProof")
	}

	// check verifiable challenges (usually by reproducing a hash)
	if err := ctx.Get(ss.p0); err != nil {
		return err
	}
	var checkv1 ssa1
	ctx.PubRand(&checkv1)		// fills in v1
	if err := ctx.Get(ss.p2); err != nil {
		return err
	}
	var checkv3 ssa3
	ctx.PubRand(&checkv3)		// fills in v3
	if err := ctx.Get(ss.p4); err != nil {
		return err
	}
	if !ss.v1.Zt.Equal(checkv1.Zt) || !ss.v3.Zc.Equal(checkv3.Zc) {
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

