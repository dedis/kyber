package bn256

// For details of the algorithms used, see "Multiplication and Squaring on
// Pairing-Friendly Fields, Devegili et al.
// http://eprint.iacr.org/2006/471.pdf.

// gfP2 implements a field of size p² as a quadratic extension of the base field
// where i²=-1.
type gfP2 struct {
	x, y gfP // value is xi+y.
}

func gfP2Encode(in *gfP2) *gfP2 {
	out := &gfP2{}
	montEncode(&out.x, &in.x)
	montEncode(&out.y, &in.y)
	return out
}

func gfP2Decode(in *gfP2) *gfP2 {
	out := &gfP2{}
	montDecode(&out.x, &in.x)
	montDecode(&out.y, &in.y)
	return out
}

func (e *gfP2) String() string {
	return "(" + e.x.String() + ", " + e.y.String() + ")"
}

func (e *gfP2) Set(a *gfP2) *gfP2 {
	e.x.Set(&a.x)
	e.y.Set(&a.y)
	return e
}

func (e *gfP2) SetZero() *gfP2 {
	e.x = gfP{0}
	e.y = gfP{0}
	return e
}

func (e *gfP2) SetOne() *gfP2 {
	e.x = gfP{0}
	e.y = *newGFp(1)
	return e
}

func (e *gfP2) IsZero() bool {
	zero := gfP{0}
	return e.x == zero && e.y == zero
}

func (e *gfP2) IsOne() bool {
	zero, one := gfP{0}, *newGFp(1)
	return e.x == zero && e.y == one
}

func (e *gfP2) Conjugate(a *gfP2) *gfP2 {
	e.y.Set(&a.y)
	gfpNeg(&e.x, &a.x)
	return e
}

func (e *gfP2) Neg(a *gfP2) *gfP2 {
	gfpNeg(&e.x, &a.x)
	gfpNeg(&e.y, &a.y)
	return e
}

func (e *gfP2) Add(a, b *gfP2) *gfP2 {
	gfpAdd(&e.x, &a.x, &b.x)
	gfpAdd(&e.y, &a.y, &b.y)
	return e
}

func (e *gfP2) Sub(a, b *gfP2) *gfP2 {
	gfpSub(&e.x, &a.x, &b.x)
	gfpSub(&e.y, &a.y, &b.y)
	return e
}

// See "Multiplication and Squaring in Pairing-Friendly Fields",
// http://eprint.iacr.org/2006/471.pdf
func (e *gfP2) Mul(a, b *gfP2) *gfP2 {
	tx, t := &gfP{}, &gfP{}
	gfpMul(tx, &a.x, &b.y)
	gfpMul(t, &b.x, &a.y)
	gfpAdd(tx, tx, t)

	ty := &gfP{}
	gfpMul(ty, &a.y, &b.y)
	gfpMul(t, &a.x, &b.x)
	gfpSub(ty, ty, t)

	e.x.Set(tx)
	e.y.Set(ty)
	return e
}

func (e *gfP2) MulScalar(a *gfP2, b *gfP) *gfP2 {
	gfpMul(&e.x, &a.x, b)
	gfpMul(&e.y, &a.y, b)
	return e
}

// MulXi sets e=ξa where ξ=i+3 and then returns e.
func (e *gfP2) MulXi(a *gfP2) *gfP2 {
	// (xi+y)(i+3) = (3x+y)i+(3y-x)
	tx := &gfP{}
	gfpAdd(tx, &a.x, &a.x)
	gfpAdd(tx, tx, &a.x)
	gfpAdd(tx, tx, &a.y)

	ty := &gfP{}
	gfpAdd(ty, &a.y, &a.y)
	gfpAdd(ty, ty, &a.y)
	gfpSub(ty, ty, &a.x)

	e.x.Set(tx)
	e.y.Set(ty)
	return e
}

func (e *gfP2) Square(a *gfP2) *gfP2 {
	// Complex squaring algorithm:
	// (xi+y)² = (x+y)(y-x) + 2*i*x*y
	tx, ty := &gfP{}, &gfP{}
	gfpSub(tx, &a.y, &a.x)
	gfpAdd(ty, &a.x, &a.y)
	gfpMul(ty, tx, ty)

	gfpMul(tx, &a.x, &a.y)
	gfpAdd(tx, tx, tx)

	e.x.Set(tx)
	e.y.Set(ty)
	return e
}

func (e *gfP2) Invert(a *gfP2) *gfP2 {
	// See "Implementing cryptographic pairings", M. Scott, section 3.2.
	// ftp://136.206.11.249/pub/crypto/pairings.pdf
	t1, t2 := &gfP{}, &gfP{}
	gfpMul(t1, &a.x, &a.x)
	gfpMul(t2, &a.y, &a.y)
	gfpAdd(t1, t1, t2)

	inv := &gfP{}
	inv.Invert(t1)

	gfpNeg(t1, &a.x)

	gfpMul(&e.x, t1, inv)
	gfpMul(&e.y, &a.y, inv)
	return e
}

// Clone makes a hard copy of the field
func (e *gfP2) Clone() gfP2 {
	n := gfP2{}
	copy(n.x[:], e.x[:])
	copy(n.y[:], e.y[:])

	return n
}

// Compute the norm in gfP of the element a in gfP2
func (e *gfP) Norm(a *gfP2) *gfP {
	t1, t2 := &gfP{}, &gfP{}
	gfpMul(t1, &a.x, &a.x)
	gfpMul(t2, &a.y, &a.y)
	gfpAdd(t1, t1, t2)

	e.Set(t1)
	return e
}

// Compute a to the power of r, where r is expressed as a [4]uint64
func (e *gfP2) Power(a *gfP2, r [4]uint64) *gfP2 {
	sum := &gfP2{gfP{0}, *newGFp(1)}
	power := &gfP2{}
	power.Set(a)
	for word := 0; word < 4; word++ {
		for bit := uint(0); bit < 64; bit++ {
			if (r[word]>>bit)&1 == 1 {
				sum.Mul(sum, power)
			}
			power.Mul(power, power)
		}
	}
	e.Set(sum)
	return e
}

func (e *gfP2) Equals(a *gfP2) bool {
	return e.x.Equals(&a.x) && e.y.Equals(&a.y)
}

// Compute the square root of the element a in gfP2
// Uses Algorithm 9 of https://eprint.iacr.org/2012/685.pdf
// In our case, n=1, and so q=p
// Returns nil if a is not a quadratic residue
func (e *gfP2) Sqrt(a *gfP2) *gfP2 {
	if a.IsZero() {
		e.SetZero()
		return e
	}
	// (p-3)/4
	pm34 := [4]uint64{0x86172b1b17822599, 0x7b96e234482d6d67,
		0x6a9bfb2e18613708, 0x23ed4078d2a8e1fe}
	// (p-1)/2
	pm12 := [4]uint64{0x0c2e56362f044b33, 0xf72dc468905adacf,
		0xd537f65c30c26e10, 0x47da80f1a551c3fc}

	a1, x0, alpha := &gfP2{}, &gfP2{}, &gfP2{}
	norm := &gfP{}
	minus1gfP := newGFp(-1)
	minus1 := &gfP2{gfP{0}, *newGFp(-1)}
	one := &gfP2{gfP{0}, *newGFp(1)}

	a1.Power(a, pm34)
	x0.Mul(a1, a)
	alpha.Mul(a1, x0)
	norm.Norm(alpha)
	if norm.Equals(minus1gfP) {
		return nil
	}
	if alpha.Equals(minus1) {
		// Set e = i * x0
		copy(e.x[:], x0.y[:])
		gfpNeg(&e.y, &x0.x)
	} else {
		b := &gfP2{}
		// Compute b = (1+alpha)^((p-1)/2)
		b.Add(alpha, one)
		b.Power(b, pm12)
		// e = b * x0
		e.Mul(b, x0)
	}
	return e
}
