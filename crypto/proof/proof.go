// Package proof implements generic support for Sigma-protocols
// and discrete logarithm proofs in the Camenisch/Stadler framework.
// For the technical foundations of this framework see
// "Proof Systems for General Statements about Discrete Logarithms" at
// ftp://ftp.inf.ethz.ch/pub/crypto/publications/CamSta97b.pdf.
package proof

import (
	"errors"
	"dissent/crypto"
)


// XXX simplify using the reflection API?
// just pass a 'struct' with the Point and Secret variables?


/*
A Pred is a composable predicate in a knowledge proof system,
representing a "knowledge specification set" in Camenisch/Stadler terminology.

Currently we require that all OR operators be above all AND operators
in the expression - i.e., no AND-of-OR predicates.
We could rewrite expressions into this form as Camenisch/Stadler suggest,
but that could run a risk of unexpected exponential blowup.
We could avoid this risk by not rewriting the expression tree,
but instead generating Pedersen commits for variables that need to "cross"
from one OR-domain to another non-mutually-exclusive one.
For now we simply require expressions to be in the appropriate form.
*/
type Pred interface {
	String() string

	// precedence-sensitive helper stringifier.
	precString(prec int) string

	// prover: recursively produce all commitments
	commit(w crypto.Secret, v []crypto.Secret) error

	// prover: given challenge, recursively produce all responses
	respond(c crypto.Secret, r []crypto.Secret) error

	// verifier: get all the commitments required in this predicate,
	// and fill the r slice with empty secrets for responses needed.
	getCommits(r []crypto.Secret) error

	// verifier: check all commitments against challenges and responses
	verify(c crypto.Secret, r []crypto.Secret) error
}


// stringification precedence levels
const (
	precNone = iota
	precOr
	precAnd
	precAtom
)


// A Term in a representation expression
type Term struct {
	Secret string	// secret multiplier for this term
	Base string	// generator for this term
}



// Atomic proof-of-representation predicate of the form y=g1x1+g2x2+...
type RepPred struct {
	prf *Proof
	val string	// public variable of which a representation is known
	sum []Term	// terms comprising the known representation
	// XXX a,b

	// Prover state
	w crypto.Secret		// secret pre-challenge
	v []crypto.Secret	// secret blinding factor for each variable

	// Verifier state
	T crypto.Point		// public commitment produced by verifier
	r []crypto.Secret	// per-variable responses produced by verifier
}

// Return a string representation of this proof-of-representation predicate,
// mainly for debugging.
func (rp *RepPred) String() string {
	return rp.precString(precNone)
}

func (rp *RepPred) precString(prec int) string {
	s := rp.val + "="
	for i := range(rp.sum) {
		if i > 0 {
			s += "+"
		}
		t := &rp.sum[i]
		s += t.Secret
		s += "*"
		s += t.Base
	}
	return s
}

func (rp *RepPred) commit(w crypto.Secret, v []crypto.Secret) error {
	prf := rp.prf
	rp.w = w

	// Create a variable-binding array if none was created higher up
	if v == nil {
		v = make([]crypto.Secret, prf.nsvars)
	}
	rp.v = v

	// Compute commit T=wY+v1G1+...+vkGk
	T := prf.s.Point()
	if w != nil {	// We're on a non-obligated branch
		T.Mul(prf.pval[rp.val],w)
	} else {	// We're on a proof-obligated branch, so w=0
		T.Null()
	}
	P := prf.s.Point()
	for i := 0; i < len(rp.sum); i++ {
		t := rp.sum[i]	// current term
		s := prf.sidx[t.Secret]

		// Choose a blinding secret the first time
		// we encounter each variable
		if v[s] == nil {
			v[s] = prf.s.Secret()
			prf.pc.PriRand(v[s])
		}
		P.Mul(prf.pval[t.Base],v[s])
		T.Add(T,P)
	}

	// Encode and send the commitment to the verifier
	return prf.pc.Put(T)
}

func (rp *RepPred) respond(c crypto.Secret, pr []crypto.Secret) error {
	prf := rp.prf

	// Create a response array for this OR-domain if not done already
	r := prf.makeResponses(pr)

	for i := range(rp.sum) {
		t := rp.sum[i]	// current term
		s := prf.sidx[t.Secret]

		// Produce a correct response for each variable
		// the first time we encounter that variable.
		if r[s] == nil {
			if rp.w != nil {
				// We're on a non-proof-obligated branch:
				// w was our challenge, v[s] is our response.
				r[s] = rp.v[s]
				continue
			}

			// We're on a proof-obligated branch,
			// so we need to calculate the correct response
			// as r = v-cx where x is the secret variable
			ri := prf.s.Secret()
			ri.Mul(c,prf.sval[t.Secret])
			ri.Sub(rp.v[s],ri)
			r[s] = ri
		}
	}

	// Send our responses if we created the array (i.e., if pr == nil)
	return prf.sendResponses(pr, r)
}

func (rp *RepPred) getCommits(pr []crypto.Secret) error {
	prf := rp.prf

	// Get the commitment for this representation
	rp.T = rp.prf.s.Point()
	if e := prf.vc.Get(rp.T); e != nil {
		return e
	}

	// Fill in the r vector with the responses we'll need.
	r := prf.makeResponses(pr)
	rp.r = r
	for i := range(rp.sum) {
		t := rp.sum[i]	// current term
		s := prf.sidx[t.Secret]
		if r[s] == nil {
			r[s] = prf.s.Secret()
		}
	}
	return nil
}

func (rp *RepPred) verify(c crypto.Secret, pr []crypto.Secret) error {
	prf := rp.prf
	r := rp.r

	// Get the needed responses if a parent didn't already
	if e := prf.getResponses(pr,r); e != nil {
		return e
	}

	// Recompute commit T=cY+r1G1+...+rkGk
	T := prf.s.Point()
	T.Mul(prf.pval[rp.val],c)
	P := prf.s.Point()
	for i := 0; i < len(rp.sum); i++ {
		t := rp.sum[i]	// current term
		s := prf.sidx[t.Secret]
		P.Mul(prf.pval[t.Base],r[s])
		T.Add(T,P)
	}
	if !T.Equal(rp.T) {
		return errors.New("invalid proof: commit mismatch")
	}

	return nil
}



// Logical AND predicate combinator
type AndPred struct {
	prf *Proof
	sub []Pred

	r []crypto.Secret	// Verifier state: responses needed
}

// Return a string representation of this AND predicate, mainly for debugging.
func (ap *AndPred) String() string {
	return ap.precString(precNone)
}

func (ap *AndPred) precString(prec int) string {
	s := ap.sub[0].precString(precAnd)
	for i := 1; i < len(ap.sub); i++ {
		s = s + " && " + ap.sub[i].precString(precAnd)
	}
	if prec != precNone && prec != precAnd {
		s = "(" + s + ")"
	}
	return s
}

func (ap *AndPred) commit(w crypto.Secret, v []crypto.Secret) error {
	prf := ap.prf

	// Create a variable-binding array if we're a top-level AND predicate
	if v == nil {
		v = make([]crypto.Secret, prf.nsvars)
	}

	// Recursively generate commitments
	for i := 0; i < len(ap.sub); i++ {
		if e := ap.sub[i].commit(w,v); e != nil {
			return e
		}
	}

	return nil
}

func (ap *AndPred) respond(c crypto.Secret, pr []crypto.Secret) error {
	prf := ap.prf

	// Recursively compute responses in all sub-predicates
	r := prf.makeResponses(pr)
	for i := range(ap.sub) {
		if e := ap.sub[i].respond(c,r); e != nil {
			return e
		}
	}
	return prf.sendResponses(pr, r)
}

func (ap *AndPred) getCommits(pr []crypto.Secret) error {
	prf := ap.prf
	r := prf.makeResponses(pr)
	ap.r = r
	for i := range(ap.sub) {
		if e := ap.sub[i].getCommits(r); e != nil {
			return e
		}
	}
	return nil
}

func (ap *AndPred) verify(c crypto.Secret, pr []crypto.Secret) error {
	prf := ap.prf
	r := ap.r
	if e := prf.getResponses(pr,r); e != nil {
		return e
	}
	for i := range(ap.sub) {
		if e := ap.sub[i].verify(c,r); e != nil {
			return e
		}
	}
	return nil
}




// Logical OR predicate combinator
type OrPred struct {
	prf *Proof
	sub []Pred
	choice int		// sub chosen for proof obligation
	w crypto.Secret		// challenge if we're non-proof-obligated
	wi []crypto.Secret	// pre-challenge for each sub
}

// Return a string representation of this OR predicate, mainly for debugging.
func (op *OrPred) String() string {
	return op.precString(precNone)
}

func (op *OrPred) precString(prec int) string {
	s := op.sub[0].precString(precOr)
	for i := 1; i < len(op.sub); i++ {
		s = s + " || " + op.sub[i].precString(precOr)
	}
	if prec != precNone && prec != precOr {
		s = "(" + s + ")"
	}
	return s
}

func (op *OrPred) Choose(choice int) *OrPred {
	op.choice = choice
	return op
}

func (op *OrPred) Choice() int {
	return op.choice
}

func (op *OrPred) commit(w crypto.Secret, v []crypto.Secret) error {
	prf := op.prf
	op.w = w
	if v != nil {		// only happens within an AND expression
		panic("can't have OR predicates within AND predicates")
	}

	// Choose pre-challenges for our subs.
	wi := make([]crypto.Secret, len(op.sub))
	op.wi = wi
	if w == nil {
		// We're on a proof-obligated branch;
		// choose random pre-challenges for only non-obligated subs.
		for i := 0; i < len(op.sub); i++ {
			if i != op.choice {
				wi[i] = prf.s.Secret()
				prf.pc.PriRand(wi[i])
			} // else wi[i] == nil for proof-obligated sub
		}
	} else {
		// Since w != nil, we're in a non-obligated branch,
		// so choose random pre-challenges for all subs
		// such that they add up to the master pre-challenge w.
		l := len(op.sub)-1	// last sub
		wl := prf.s.Secret().Set(w)
		for i := 0; i < l; i++ {	// choose all but last
			wi[i] = prf.s.Secret()
			prf.pc.PriRand(wi[i])
			wl.Sub(wl,wi[i])
		}
		wi[l] = wl
	}

	// Now recursively choose commitments within each sub
	for i := 0; i < len(op.sub); i++ {
		// Fresh variable-blinding secrets for each pre-commitment
		if e := op.sub[i].commit(wi[i],nil); e != nil {
			return e
		}
	}

	return nil
}

func (op *OrPred) respond(c crypto.Secret, pr []crypto.Secret) error {
	if pr != nil {
		panic("OR predicates can't be nested in anything else")
	}

	ci := op.wi
	if op.w == nil {
		// Calculate the challenge for the proof-obligated subtree
		cs := op.prf.s.Secret().Set(c)
		for i := 0; i < len(op.sub); i++ {
			if i != op.choice {
				cs.Sub(cs,ci[i])
			}
		}
		if op.choice < 0 {
			panic("oops, didn't make a choice in OR predicate: "+
				op.String())
		}
		ci[op.choice] = cs
	}

	// If there's more than one choice, send all our sub-challenges.
	if len(op.sub) > 1 {
		if e := op.prf.pc.Put(ci); e != nil {
			return e
		}
	}

	// Recursively compute responses in all subtrees
	for i := range(op.sub) {
		if e := op.sub[i].respond(ci[i],nil); e != nil {
			return e
		}
	}

	return nil
}

// Get from the verifier all the commitments needed for this predicate
func (op *OrPred) getCommits(r []crypto.Secret) error {
	for i := range(op.sub) {
		if e := op.sub[i].getCommits(nil); e != nil {
			return e
		}
	}
	return nil
}

func (op *OrPred) verify(c crypto.Secret, pr []crypto.Secret) error {
	prf := op.prf
	if pr != nil {
		panic("OR predicates can't be in anything else")
	}

	// Get the prover's sub-challenges
	nsub := len(op.sub)
	ci := make([]crypto.Secret, nsub)
	if nsub > 1 {
		if e := op.prf.vc.Get(ci); e != nil {
			return e
		}

		// Make sure they add up to the parent's composite challenge
		csum := prf.s.Secret().Zero()
		for i := 0; i < nsub; i++ {
			csum.Add(csum, ci[i])
		}
		if !csum.Equal(c) {
			return errors.New("invalid proof: bad sub-challenges")
		}

	} else {	// trivial single-sub OR
		ci[0] = c
	}

	// Recursively verify all subs
	for i := range(op.sub) {
		if e := op.sub[i].verify(ci[i], nil); e != nil {
			return e
		}
	}

	return nil
}



/*
type lin struct {
	a1,a2,b crypto.Secret
	x1,x2 PriVar
}
*/

// Construct a predicate asserting a linear relationship a1x1+a2x2=b,
// where a1,a2,b are public values and x1,x2 are secrets.
/*
func (p *Prover) Linear(a1,a2,b crypto.Secret, x1,x2 PriVar) {
	return &lin{a1,a2,b,x1,x2}
}
*/



/*
Generic implementation of basic zero-knowledge proofs 
of the form described by Camenisch/Stadler in
Proof Systems for General Statements about Discrete Logarithms".

XXX supports multiple groups? but each variable in only one group.
*/
type Proof struct {
	s crypto.Suite
	//g []Group
	pc ProverContext
	vc VerifierContext

	nsvars int		// number of Secret variables
	npvars int		// number of Point variables

	// Secret and Point variable names
	svar, pvar []string

	// Maps from strings to variable indexes
	sidx, pidx map[string]int

	// Proof state
	pval map[string]crypto.Point	// values of public Point variables
	sval map[string]crypto.Secret	// values of private Secret variables
}

func NewProof(s crypto.Suite, svar,pvar []string) *Proof {
	var prf Proof
	prf.Init(s,svar,pvar)
	return &prf
}

func (prf *Proof) Init(s crypto.Suite, svar,pvar []string) {
	prf.s = s
	prf.nsvars = len(svar)
	prf.npvars = len(pvar)
	prf.svar = svar
	prf.pvar = pvar

	prf.sidx = make(map[string]int)
	for i := range(svar) {
		prf.sidx[svar[i]] = i
	}

	prf.pidx = make(map[string]int)
	for i := range(pvar) {
		prf.pidx[pvar[i]] = i
	}
}

// Create a predicate representing the knowledge of a Secret that,
// multiplied by a given public base, yields a given public point.
func (prf *Proof) Log(pointVar,secretVar,baseVar string) *RepPred {
	return prf.Rep(pointVar, Term{secretVar,baseVar})
}

// Create a predicate represending the knowledge of
// a representation of a public Point variable
// as the sum of one or more Terms,
// each involving a public Point base and a secret multiplier.
func (prf *Proof) Rep(pointVar string, sum ...Term) *RepPred {
	rp := RepPred{}
	rp.prf = prf
	rp.val = pointVar
	rp.sum = sum
	return &rp
}

// Construct a Logical AND predicate combining multiple sub-predicates.
// The prover must demonstrate all sub-predicates to be true.
func (prf *Proof) And(sub ...Pred) *AndPred {
	ap := AndPred{}
	ap.prf = prf
	ap.sub = sub
	return &ap
}

// Construct a Logical OR predicate combining multiple sub-predicates.
// The prover need only demonstrate at least one sub-predicate to be true,
// and the generated proof reveals nothing about which one is true.
func (prf *Proof) Or(sub ...Pred) *OrPred {
	op := OrPred{}
	op.prf = prf
	op.sub = sub
	op.choice = -1
	return &op
}

// Make a response-array if that wasn't already done in a parent predicate.
func (prf *Proof) makeResponses(pr []crypto.Secret) []crypto.Secret {
	if pr == nil {
		return make([]crypto.Secret, prf.nsvars)
	}
	return pr
}

// Transmit our response-array if a corresponding makeResponses() created it.
func (prf *Proof) sendResponses(pr []crypto.Secret, r []crypto.Secret) error {
	if pr == nil {
		for i := range(r) {
			// Send responses only for variables
			// that were used in this OR-domain.
			if r[i] != nil {
				if e := prf.pc.Put(r[i]); e != nil {
					return e
				}
			}
		}
	}
	return nil
}

// In the verifier, get the responses at the top of an OR-domain,
// if a corresponding makeResponses() call created it.
func (prf *Proof) getResponses(pr []crypto.Secret, r []crypto.Secret) error {
	if pr == nil {
		for i := range(r) {
			if r[i] != nil {
				if e := prf.vc.Get(r[i]); e != nil {
					return e
				}
			}
		}
	}
	return nil
}

func (prf *Proof) Prove(p Pred, sval map[string]crypto.Secret, 
			pval map[string]crypto.Point, pc ProverContext) error {
	prf.pc = pc
	prf.sval = sval
	prf.pval = pval

	// Generate all commitments
	if e := p.commit(nil,nil); e != nil {
		return e
	}

	// Generate top-level challenge from public randomness
	c := prf.s.Secret()
	pc.PubRand(c)

	// Generate all responses based on master challenge
	return p.respond(c,nil)
}

func (prf *Proof) Verify(p Pred, pval map[string]crypto.Point,
			vc VerifierContext) error {
	prf.vc = vc
	prf.pval = pval

	// Get the commitments from the verifier,
	// and calculate the sets of responses we'll need for each OR-domain.
	if e := p.getCommits(nil); e != nil {
		return e
	}

	// Produce the top-level challenge
	c := prf.s.Secret()
	vc.PubRand(c)

	// Check all the responses and sub-challenges against the commitments.
	return p.verify(c,nil)
}

// Produce a higher-order Prover embodying a given proof predicate.
// XXX may only be used once safely; we should probably fix this.
func (prf *Proof) Prover(p Pred, sval map[string]crypto.Secret, 
			pval map[string]crypto.Point) Prover {

	return Prover(func(ctx ProverContext)error{
		return prf.Prove(p, sval, pval, ctx)
	})
}

// Produce a higher-order Verifier embodying a given proof predicate.
// XXX may only be used once safely; we should probably fix this.
func (prf *Proof) Verifier(p Pred, pval map[string]crypto.Point) Verifier {

	return Verifier(func(ctx VerifierContext)error{
		return prf.Verify(p, pval, ctx)
	})
}

