package crypto

import (
	"fmt"
	"hash"
	"errors"
	"math/big"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
)


// Basic, unoptimized reference implementation of Twisted Edwards curves.
// Twisted Edwards curves (TEC's) are elliptic curves of the form
//
//	ax^2 + y^2 = c*(1 + dx^2y^2)
//
// for some scalars c, d over some field K.
// We assume K is a (finite) prime field for a large prime p.
// 
// This reference implementation is mainly intended for debugging and testing
// and instructional uses, not for production use.
//
type edwardsPoint struct {
	x,y ModInt
	c *edwardsCurve
}

func (P *edwardsPoint) String() string {
	return fmt.Sprintf("(%s,%s)", P.x.String(), P.y.String())
}

// Create a new ModInt representing a coordinate on this curve,
// with a given int64 integer value for constant-initialization convenience.
func (P *edwardsPoint) coord(v int64) *ModInt {
	return NewModInt(v, &P.c.p)
}

func (P *edwardsPoint) Len() int {
	return (P.y.M.BitLen() + 7 + 1) / 8
}

// Encode an Edwards curve point.
func (P *edwardsPoint) Encode() []byte {

	// Encode the y-coordinate
	b := P.y.Encode()

	// Encode the sign of the x-coordinate.
	if P.y.M.BitLen() & 7 == 0 {
		// No unused bits at the top of y-coordinate encoding,
		// so we must prepend a whole byte.
		b = append(make([]byte,1), b...)
	}
	if P.coordSign(&P.x) != 0 {
		b[0] |= 0x80
	}

	return b
}

// Decode an Edwards curve point.
func (P *edwardsPoint) Decode(b []byte) error {

	// Extract the sign of the x-coordinate
	xsign := uint(b[0] >> 7)
	b[0] &^= 0x80

	// Extract the y-coordinate
	P.y.V.SetBytes(b)

	// Compute the corresponding x-coordinate
	if !P.solveForX() {
		return errors.New("invalid elliptic curve point")
	}
	if P.coordSign(&P.x) != xsign {
		P.x.Neg(&P.x)
	}

	return nil
}

// Equality test for two Points on the same curve
func (P *edwardsPoint) Equal(P2 Point) bool {
	E2 := P2.(*edwardsPoint)
	return P.x.Equal(&E2.x) && P.y.Equal(&E2.y)
}

// Set point to be equal to P2.
func (P *edwardsPoint) Set(P2 Point) Point {
	E2 := P2.(*edwardsPoint)
	P.c = E2.c
	P.x.Set(&E2.x)
	P.y.Set(&E2.y)
	return P
}

// Set to the neutral element, which is (0,1) for twisted Edwards curves.
func (P *edwardsPoint) Null() Point {
	P.Set(&P.c.I)
	return P
}

// Set to the standard base point for this curve
func (P *edwardsPoint) Base() Point {
	P.Set(&P.c.B)
	return P
}

// Test the sign of an x or y coordinate.
// We use bit 0 of the coordinate as the sign bit.
func (P *edwardsPoint) coordSign(i *ModInt) uint {
	return i.V.Bit(0)
}

// Test if a supposed point is on the curve,
// by checking the characteristic equation for Edwards curves:
//
//	a*x^2 + y^2 = 1 + d*x^2*y^2
//
func (P *edwardsPoint) onCurve() bool {
	var xx,yy,l,r ModInt

	xx.Mul(&P.x,&P.x)			// xx = x^2
	yy.Mul(&P.y,&P.y)			// yy = y^2

	l.Mul(&P.c.a,&xx).Add(&l,&yy)		// l = a*x^2 + y^2
	r.Mul(&P.c.d,&xx).Mul(&r,&yy).Add(P.c.one,&r)
						// r = 1 + d*x^2*y^2
	return l.Equal(&r)
}

// Given a y-coordinate, solve for the x-coordinate on the curve,
// using the characteristic equation rewritten as.
//
//	x^2 = (1 - y^2)/(a - d*y^2)
//	ax^2 - d*x^2*y^2 = 1 - y^2
//	ax^2 + y^2 = 1 + d*x^2*y^2
//
// Returns true on success,
// false if there is no x-coordinate corresponding to the chosen y-coordinate.
//
func (P *edwardsPoint) solveForX() bool {
	var yy,t1,t2 ModInt

	yy.Mul(&P.y,&P.y)			// yy = y^2
	t1.Sub(P.c.one,&yy)			// t1 = 1 - y^-2
	t2.Mul(&P.c.d,&yy).Sub(&P.c.a,&t2)	// t2 = a - d*y^2
	t2.Div(&t1,&t2)				// t2 = x^2
	return P.x.Sqrt(&t2)			// may fail if not a square
}

func (P *edwardsPoint) PickLen() int {
	// Reserve at least 8 most-significant bits for randomness,
	// and the least-significant 8 bits for embedded data length.
	// (Hopefully it's unlikely we'll need >=2048-bit curves soon.)
	return (P.x.M.BitLen() - 8 - 8) / 8
}

func (P *edwardsPoint) Pick(data []byte,rand cipher.Stream) (Point, []byte) {

	l := P.y.Len()
	dl := P.PickLen()
	if dl > len(data) {
		dl = len(data)
	}

	for {
		// Pick a random y-coordinate, with optional embedded data
		b := RandomBits(uint(P.y.M.BitLen()), false, rand)
		if data != nil {
			b[l-1] = byte(dl)	// Encode length in low 8 bits
			copy(b[l-dl-1:l-1],data) // Copy in data to embed
		}
		P.y.V.SetBytes(b).Mod(&P.y.V,P.y.M)

		if !P.solveForX() {	// Find a corresponding x-coordinate
			continue	// none, retry
		}

		// Pick a random sign for the x-coordinate
		b = b[0:1]
		rand.XORKeyStream(b,b)
		if P.coordSign(&P.x) != uint(b[0] >> 7) {
			P.x.Neg(&P.x)
		}

		if !P.onCurve() {
			panic("Pick generated a bad point")
		}

		return P,data[dl:]
	}
}

// Extract embedded data from a point group element
func (P *edwardsPoint) Data() ([]byte,error) {
	b := P.y.V.Bytes()
	l := P.y.Len()
	if len(b) < l {		// pad leading zero bytes if necessary
		b = append(make([]byte,l-len(b)), b...)
	}
	dl := int(b[l-1])
	if dl > P.PickLen() {
		return nil,errors.New("invalid embedded data length")
	}
	return b[l-dl-1:l-1],nil
}

// Add two points using the basic unified addition laws for Edwards curves:
//
//	x' = ((x1*y2 + x2*y1) / (1 + d*x1*x2*y1*y2))
//	y' = ((y1*y2 - a*x1*x2) / (1 - d*x1*x2*y1*y2))
//
func (P *edwardsPoint) Add(P1,P2 Point) Point {
	E1 := P1.(*edwardsPoint)
	E2 := P2.(*edwardsPoint)
	x1,y1 := E1.x,E1.y
	x2,y2 := E2.x,E2.y

	var t1,t2,dm,nx,dx,ny,dy ModInt

	// Reused part of denominator: dm = d*x1*x2*y1*y2
	dm.Mul(&P.c.d,&x1).Mul(&dm,&x2).Mul(&dm,&y1).Mul(&dm,&y2)

	// x' numerator/denominator
	nx.Add(t1.Mul(&x1,&y2),t2.Mul(&x2,&y1))
	dx.Add(P.c.one,&dm)

	// y' numerator/denominator
	ny.Sub(t1.Mul(&y1,&y2),t2.Mul(&x1,&x2).Mul(&P.c.a,&t2))
	dy.Sub(P.c.one,&dm)

	// result point
	P.x.Div(&nx,&dx)
	P.y.Div(&ny,&dy)
	return P
}

// Point doubling, which for Edwards curves can be accomplished
// simply by adding a point to itself (no exceptions for equal input points).
func (p *edwardsPoint) double(P Point) Point {
	return P.Add(P,P)
}

// Subtract points so that their secrets subtract homomorphically
func (P *edwardsPoint) Sub(A,B Point) Point {
	var nB edwardsPoint
	return P.Add(A,nB.Neg(B))
}

// Find the negative of point A.
// For Edwards curves, the negative of (x,y) is (-x,y).
func (P *edwardsPoint) Neg(A Point) Point {
	E := A.(*edwardsPoint)
	P.c = E.c
	P.x.Neg(&E.x)
	P.y.Set(&E.y)
	return P
}

// Multiply point p by scalar s using the repeated doubling method.
func (P *edwardsPoint) Mul(G Point, s Secret) Point {
	v := s.(*ModInt).V
	if G == nil {
		return P.Base().Mul(P,s)
	}
	var T edwardsPoint	// Must use temporary in case G == P
	T.Set(&P.c.I)		// Initialize to identity element (0,1)
	for i := v.BitLen()-1; i >= 0; i-- {
		T.double(&T)
		if v.Bit(i) != 0 {
			T.Add(&T, G)
		}
	}
	P.Set(&T)
	return P
}


type edwardsCurve struct {
	name string		// Well-known name of curve

	p big.Int		// Large prime defining the underlying field
	r big.Int		// Group order of the standard generator

	a ModInt		// Edwards curve equation parameter a
	d ModInt		// Edwards curve equation parameter d

	I edwardsPoint		// Constant identity/null point (0,1)
	B edwardsPoint		// Standard base point

	zero,one *ModInt	// Constant ModInts with correct modulus
}

func (c *edwardsCurve) String() string {
	return c.name
}

func (c *edwardsCurve) SecretLen() int {
	return (c.r.BitLen() + 7) / 8
}

func (c *edwardsCurve) Secret() Secret {
	return NewModInt(0, &c.r)
}

func (c *edwardsCurve) PointLen() int {
	return (c.p.BitLen() + 7 + 1) / 8
}

func (c *edwardsCurve) Point() Point {
	P := new(edwardsPoint)
	P.c = c
	P.Set(&c.I)
	return P
}

// Initialize a twisted Edwards curve with given parameters.
//
//	p: prime modulus of underlying field.
//	r: prime order of standard base point.
//	a,d: Edwards curve equation parameters.
//	bx,by: standard base point.
//
func (c *edwardsCurve) init(name string, p,r,a,d,bx,by *big.Int) {
	c.name = name

	c.p.Set(p)		// prime modulus of underlying field
	c.r.Set(r)		// prime order of base point

	// Useful ModInt constants for this curve
	c.zero = &c.I.y
	c.one = &c.I.y

	// Edwards curve parameters
	c.a.Init(a,&c.p)
	c.d.Init(d,&c.p)

	// Identity element is (0,1)
	c.I.c = c
	c.I.x.Init64(0, &c.p)
	c.I.y.Init64(1, &c.p)

	// Base point B
	c.B.c = c
	c.B.x.Init(bx, &c.p)
	c.B.y.Init(by, &c.p)
	if !c.B.onCurve() {
		panic("init25519: base point not on curve!?")
	}
}

func (c *edwardsCurve) init25519() {
	c.name = "Ed25519"

	// p = 2^255 - 19
	c.p.SetBit(zero, 255, 1)
	c.p.Sub(&c.p, big.NewInt(19))
	//println("p: "+c.p.String())

	// r = 2^252 + 27742317777372353535851937790883648493
	c.r.SetString("27742317777372353535851937790883648493", 10)
	c.r.SetBit(&c.r, 252, 1)

	// a = -1
	c.a.Init64(-1, &c.p)
	//println("a: "+c.a.String())

	// d = -121665/121666
	c.d.Init64(-121665, &c.p).Div(&c.d,NewModInt(121666, &c.p))
	//println("d: "+c.d.String())

	// Identity element is (0,1)
	c.I.c = c
	c.I.x.Init64(0, &c.p)
	c.I.y.Init64(1, &c.p)
	c.zero = &c.I.y
	c.one = &c.I.y
	if !c.I.onCurve() {
		panic("init25519: identity point not on curve!?")
	}

	var t ModInt
	t.Set(&c.d)
	t.Mul(&t,NewModInt(-121666,&c.p)).Div(&t,NewModInt(121665, &c.p))
	//println("t: "+t.String())

	// Base point B is the unique (x,4/5) such that x is positive
	c.B.c = c
	c.B.y.Init64(4, &c.p).Div(&c.B.y,NewModInt(5, &c.p))
	ok := c.B.solveForX()
	if !ok {
		panic("init25519: invalid base point!?")
	}
	//println("B: "+c.B.String())
	if c.B.coordSign(&c.B.x) != 0 {
		c.B.x.Neg(&c.B.x)	// take the positive square root
	}
	//println("-B: "+c.B.String())
	if !c.B.onCurve() {
		panic("init25519: base point not on curve!?")
	}
}

func (c *edwardsCurve) initE382() {
	var p,r,rs,a,d,bx,by big.Int
	p.SetBit(zero,382,1).Sub(&p,big.NewInt(105))	// p = 2^382-105
	rs.SetString("1030303207694556153926491950732314247062623204330168346855",10)
	r.SetBit(zero,380,1).Sub(&r,&rs)
	a.SetInt64(1)
	d.SetInt64(-67254)
	bx.SetString("3914921414754292646847594472454013487047137431784830634731377862923477302047857640522480241298429278603678181725699",10)
	by.SetString("17",10)
	c.init("E382",&p,&r,&a,&d,&bx,&by)
}

func (c *edwardsCurve) init41417() {
	var p,r,rs,a,d,bx,by big.Int
	p.SetBit(zero,414,1).Sub(&p,big.NewInt(17))
	rs.SetString("33364140863755142520810177694098385178984727200411208589594759",10)
	r.SetBit(zero,411,1).Sub(&r,&rs)
	a.SetInt64(1)
	d.SetInt64(3617)
	bx.SetString("17319886477121189177719202498822615443556957307604340815256226171904769976866975908866528699294134494857887698432266169206165",10)
	by.SetString("34",10)
	c.init("Ed41417",&p,&r,&a,&d,&bx,&by)
}

func (c *edwardsCurve) initE521() {
	var p,r,rs,a,d,bx,by big.Int
	p.SetBit(zero,521,1).Sub(&p,one)
	rs.SetString("337554763258501705789107630418782636071904961214051226618635150085779108655765",10)
	r.SetBit(zero,519,1).Sub(&r,&rs)
	a.SetInt64(1)
	d.SetInt64(-376014)
	bx.SetString("1571054894184995387535939749894317568645297350402905821437625181152304994381188529632591196067604100772673927915114267193389905003276673749012051148356041324",10)
	by.SetString("12",10)
	c.init("E521",&p,&r,&a,&d,&bx,&by)
}


// Edwards curves represented in extended coordinates as specified in:
//
//	Twisted Edwards Curves Revisited
//	http://eprint.iacr.org/2008/522
//
type extEdwardsPoint struct {
	X,Y,Z,T big.Int
	c *extEdwardsCurve
}




type extEdwardsCurve struct {
	edwardsCurve		// Note that parameter a must be = -1
}

/*
func (c *extEdwardsCurve) Point() Point {
	P := new(extEdwardsPoint)
	P.c = c
	return P
}
*/


type suiteEd25519 struct {
	edwardsCurve
} 
// XXX non-NIST ciphers?

// SHA256 hash function
func (s *suiteEd25519) HashLen() int { return sha256.Size }
func (s *suiteEd25519) Hash() hash.Hash {
	return sha256.New()
}

// AES128-CTR stream cipher
func (s *suiteEd25519) KeyLen() int { return 16 }
func (s *suiteEd25519) Stream(key []byte) cipher.Stream {
	aes, err := aes.NewCipher(key)
	if err != nil {
		panic("can't instantiate AES: " + err.Error())
	}
	iv := make([]byte,16)
	return cipher.NewCTR(aes,iv)
}

// Ciphersuite based on AES-128, SHA-256, and the Ed25519 curve.
func NewAES128SHA256Ed25519() Suite {
	suite := new(suiteEd25519)
	suite.init25519()
//	suite.initE382()
//	suite.init41417()
//	suite.initE521()
	return suite
}

