//go:build !constantTime

package bn256

import "go.dedis.ch/kyber/v4"

// HashG1 implements a hashing function into the G1 group.
//
// dst represents domain separation tag, similar to salt, for the hash.
func HashG1(msg, dst []byte) kyber.Point {
	return mapToCurve(hashToBase(msg, dst))
}

//nolint:funlen
func mapToCurve(t *gfP) kyber.Point {
	one := *newGFp(1)

	// calculate w = (s * t)/(1 + B + t^2)
	// we calculate w0 = s * t * (1 + B + t^2) and inverse of it, so that w = (st)^2/w0
	// and then later x3 = 1 + (1 + B + t^2)^4/w0^2
	w := &gfP{}

	// Computing a = (1 + B + t^2)
	a := &gfP{}
	t2 := &gfP{}
	gfpMul(t2, t, t)
	gfpAdd(a, curveB, t2)
	gfpAdd(a, a, &one)

	st := &gfP{}
	gfpMul(st, s, t)

	w0 := &gfP{}
	gfpMul(w0, st, a)
	w0.Invert(w0)

	gfpMul(w, st, st)
	gfpMul(w, w, w0)

	e := sign0(t)
	cp := &curvePoint{z: one, t: one}

	// calculate x1 = ((-1 + s) / 2) - t * w
	tw := &gfP{}
	gfpMul(tw, t, w)
	x1 := &gfP{}
	gfpSub(x1, sMinus1Over2, tw)

	// check if y=x1^3+3 is a square
	y := &gfP{}
	y.Set(x1)
	gfpMul(y, x1, x1)
	gfpMul(y, y, x1)
	gfpAdd(y, y, curveB)
	if legendre(y) == 1 {
		cp.x = *x1
		y.Sqrt(y)
		if e != sign0(y) {
			gfpNeg(y, y)
		}
		cp.y = *y

		pg1 := pointG1{cp}
		return pg1.Clone()
	}

	// calculate x2 = -1 - x1
	x2 := newGFp(-1)
	gfpSub(x2, x2, x1)

	// check if y=x2^3+3 is a square
	y.Set(x2)
	gfpMul(y, x2, x2)
	gfpMul(y, y, x2)
	gfpAdd(y, y, curveB)
	if legendre(y) == 1 {
		cp.x = *x2
		y.Sqrt(y)
		if e != sign0(y) {
			gfpNeg(y, y)
		}
		cp.y = *y

		pg1 := pointG1{cp}
		return pg1.Clone()
	}

	// calculate x3 = 1 + (1/ww) = 1 + a^4 * w0^2
	x3 := &gfP{}
	gfpMul(x3, a, a)
	gfpMul(x3, x3, x3)
	gfpMul(x3, x3, w0)
	gfpMul(x3, x3, w0)
	gfpAdd(x3, x3, &one)

	y.Set(x3)
	gfpMul(y, x3, x3)
	gfpMul(y, y, x3)
	gfpAdd(y, y, curveB)

	cp.x = *x3
	y.Sqrt(y)
	if e != sign0(y) {
		gfpNeg(y, y)
	}
	cp.y = *y

	pg1 := pointG1{cp}
	return pg1.Clone()
}
