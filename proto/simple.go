package proto

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

type SimpleShuffleProof struct {
	p0 ssa0
	v1 ssa1
	p2 ssa2
	v3 ssa3
	p4 ssa4
}

// Simple helper to compute G^{ab-cd} for Theta vector computation
func thenc(group crypto.Group, G crypto.Point,
		a,b,c,d crypto.Secret) crypto.Point {

	var ab,cd crypto.Secret
	if a != nil {
		ab = group.Secret().Mul(a,b)
	} else {
		ab = group.Secret().Zero()
	}
	if c != nil {
		if d != nil {
			cd = group.Secret().Mul(c,d)
		} else {
			cd = c
		}
	} else {
		cd = group.Secret().Zero()
	}
	return group.Point().Encrypt(G,ab.Sub(ab,cd))
}

// The "Simple k-shuffle" defined in section 3 of
// Neff, "Verifiable Mixing (Shuffling) of ElGamal Pairs", 2004.
// The Secret vector y must be a permutation of Secret vector x
// but with all elements multiplied by common Secret gamma.
func SimpleShuffleProve(group crypto.Group, G crypto.Point, gamma crypto.Secret,
			x,y []crypto.Secret, rand cipher.Stream,
			proof *SimpleShuffleProof, v SigmaVerifier) {

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
		proof.p0.X[i] = group.Point().Encrypt(G,x[i])
		proof.p0.Y[i] = group.Point().Encrypt(G,y[i])
	}
	v.Put(proof.p0)

	// V step 1
	v.Get(proof.v1)
	t := proof.v1.t

	// P step 2
	gamma_t := group.Secret().Mul(gamma,t)
	xhat := make([]crypto.Secret, k)
	yhat := make([]crypto.Secret, k)
	for i := 0; i < k; i++ {	// (5) and (6) xhat,yhat vectors
		xhat[i] = group.Secret().Sub(x[i], t)
		yhat[i] = group.Secret().Sub(x[i], gamma_t)
	}
	thlen := 2*k-1			// (7) theta and Theta vectors
	theta := make([]crypto.Secret, thlen)
	Theta := make([]crypto.Point, thlen+1)
	for i := 0; i < thlen; i++ {
		theta[i] = group.Secret().Pick(rand)
	}
	Theta[0] = thenc(group, G, nil, nil, theta[0], yhat[0])
	for i := 1; i < k; i++ {
		Theta[i] = thenc(group, G, theta[i-1], xhat[i],
					theta[i], yhat[i])
	}
	for i := k; i < thlen; i++ {
		Theta[i] = thenc(group, G, theta[i-1], gamma,
					theta[i], nil)
	}
	Theta[thlen] = thenc(group, G, theta[thlen-1], gamma, nil, nil)
	proof.p2.Theta = Theta
	v.Put(proof.p2)

	// V step 3
	v.Get(proof.v3)
	c := proof.v3.c

	// P step 4
	alpha := make([]crypto.Secret, thlen)
	runprod := group.Secret().Set(c)
	for i := 0; i < k; i++ {		// (8)
		runprod.Mul(runprod,xhat[i])
		runprod.Div(runprod,yhat[i])
		alpha[i] = group.Secret().Add(theta[i],runprod)
	}
	gammainv := group.Secret().Inv(gamma)
	rungamma := group.Secret().Set(c)
	for i := 1; i < k; i++ {
		rungamma.Mul(rungamma,gammainv)
		alpha[thlen-i] = group.Secret().Add(theta[thlen-i],rungamma)
	}
	proof.p4.alpha = alpha
	v.Put(proof.p4)

	return &proof
}

// Simple helper to verify Theta elements,
// by checking whether A^a*B^-b = T.
// P,Q,s are simply "scratch" crypto.Point/Secrets reused for efficiency.
func thver(A,B,T,P,Q crypto.Point, a,b,s crypto.Secret) bool {
	P.Encrypt(A,a)
	Q.Encrypt(B,s.Neg(b))
	P.Add(P,Q)
	return P.Equal(T)
}

// Verifier for Neff simple k-shuffle proofs.
func SimpleShuffleVerify(group crypto.Group, G crypto.Point, Gamma crypto.Point,
			proof *SimpleShuffleProof, v SigmaVerifier) error {

	// extract proof transcript
	X := proof.in.X
	Y := proof.in.Y
	t := proof.v1.t
	Theta := proof.p2.Theta
	c := proof.v3.c
	alpha := proof.p4.alpha

	// Validate all vector lengths
	k := len(Y)
	thlen := 2*k-1
	if k <= 1 || len(Y) != k || len(Theta) != thlen+1 ||
			len(alpha) != thlen {
		return errors.New("malformed SimpleShuffleProof")
	}

	// check verifiable challenges (usually by reproducing a hash)
	v.Put(proof.p0)
	var checkv1 ssa1
	v.Get(checkv1)		// fills in v1
	v.Put(proof.p2)
	var checkv3 ssa3
	v.Get(checkv3)		// fills in v3
	v.Put(proof.p4)
	if !proof.v1.t.Equal(checkv1.t) || !proof.v3.c.Equal(checkv3.c) {
		return errors.New("incorrect challenges in SimpleShuffleProof")
	}

	// Verifier step 5
	negt := group.Secret().Neg(t)
	U := group.Point().Encrypt(G,negt)
	W := group.Point().Encrypt(Gamma,negt)
	Xhat := make([]crypto.Point,k)
	Yhat := make([]crypto.Point,k)
	for i := 0; i < k; i++ {
		Xhat[i] = group.Point().Add(X[i],U)
		Yhat[i] = group.Point().Add(Y[i],W)
	}
	P := group.Point()	// scratch variables
	Q := group.Point()
	s := group.Secret()
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

