package edwards

import (
	"errors"
	"crypto/cipher"
	"dissent/crypto"
)


// Generic "abstract base class" for Edwards curves,
// embodying functionality independent of internal Point representation.
type curve struct {
	Param			// Edwards curve parameters

	a crypto.ModInt		// Edwards curve equation parameter a
	d crypto.ModInt		// Edwards curve equation parameter d

	zero,one crypto.ModInt	// Constant ModInts with correct modulus
}

func (c *curve) SecretLen() int {
	return (c.R.BitLen() + 7) / 8
}

func (c *curve) Secret() crypto.Secret {
	return crypto.NewModInt(0, &c.R)
}

func (c *curve) PointLen() int {
	return (c.P.BitLen() + 7 + 1) / 8
}

// Initialize a twisted Edwards curve with given parameters.
func (c *curve) init(p *Param) *curve {
	c.Param = *p

	// Edwards curve parameters as ModInts for convenience
	c.a.Init(&p.A,&p.P)
	c.d.Init(&p.D,&p.P)
         
	// Useful ModInt constants for this curve
	c.zero.Init64(0, &c.P)
	c.one.Init64(1, &c.P)

	return c
}

// Test the sign of an x or y coordinate.
// We use the least-significant bit of the coordinate as the sign bit.
func (c *curve) coordSign(i *crypto.ModInt) uint {
	return i.V.Bit(0)
}

// Encode an Edwards curve point.
func (c *curve) encodePoint(x,y *crypto.ModInt) []byte {

	// Encode the y-coordinate
	b := y.Encode()

	// Encode the sign of the x-coordinate.
	if y.M.BitLen() & 7 == 0 {
		// No unused bits at the top of y-coordinate encoding,
		// so we must prepend a whole byte.
		b = append(make([]byte,1), b...)
	}
	if c.coordSign(x) != 0 {
		b[0] |= 0x80
	}

	return b
}

// Decode an Edwards curve point into the given x,y coordinates.
func (c *curve) decodePoint(b []byte, x,y *crypto.ModInt) error {

	// Extract the sign of the x-coordinate
	xsign := uint(b[0] >> 7)
	b[0] &^= 0x80

	// Extract the y-coordinate
	y.V.SetBytes(b)

	// Compute the corresponding x-coordinate
	if !c.solveForX(x,y) {
		return errors.New("invalid elliptic curve point")
	}
	if c.coordSign(x) != xsign {
		x.Neg(x)
	}

	return nil
}

// Given a y-coordinate, solve for the x-coordinate on the curve,
// using the characteristic equation rewritten as:
//
//	x^2 = (1 - y^2)/(a - d*y^2)
//
// Returns true on success,
// false if there is no x-coordinate corresponding to the chosen y-coordinate.
//
func (c *curve) solveForX(x,y *crypto.ModInt) bool {
	var yy,t1,t2 crypto.ModInt

	yy.Mul(y,y)				// yy = y^2
	t1.Sub(&c.one,&yy)			// t1 = 1 - y^-2
	t2.Mul(&c.d,&yy).Sub(&c.a,&t2)		// t2 = a - d*y^2
	t2.Div(&t1,&t2)				// t2 = x^2
	return x.Sqrt(&t2)			// may fail if not a square
}

// Test if a supposed point is on the curve,
// by checking the characteristic equation for Edwards curves:
//
//	a*x^2 + y^2 = 1 + d*x^2*y^2
//
func (c *curve) onCurve(x,y *crypto.ModInt) bool {
	var xx,yy,l,r crypto.ModInt

	xx.Mul(x,x)				// xx = x^2
	yy.Mul(y,y)				// yy = y^2

	l.Mul(&c.a,&xx).Add(&l,&yy)		// l = a*x^2 + y^2
	r.Mul(&c.d,&xx).Mul(&r,&yy).Add(&c.one,&r)
						// r = 1 + d*x^2*y^2
	return l.Equal(&r)
}

// Return number of bytes that can be embedded into points on this curve.
func (c *curve) pickLen() int {
	// Reserve at least 8 most-significant bits for randomness,
	// and the least-significant 8 bits for embedded data length.
	// (Hopefully it's unlikely we'll need >=2048-bit curves soon.)
	return (c.P.BitLen() - 8 - 8) / 8
}

// Pick a [pseudo-]random curve point with optional embedded data,
// filling in the point's x,y coordinates
// and returning any remaining data not embedded.
func (c *curve) pickPoint(data []byte, rand cipher.Stream,
			x,y *crypto.ModInt) []byte {

	// How much data to embed?
	l := y.Len()
	dl := c.pickLen()
	if dl > len(data) {
		dl = len(data)
	}

	// Retry until we find a valid point
	for {
		// Pick a random y-coordinate, with optional embedded data
		b := crypto.RandomBits(uint(c.P.BitLen()), false, rand)
		if data != nil {
			b[l-1] = byte(dl)	// Encode length in low 8 bits
			copy(b[l-dl-1:l-1],data) // Copy in data to embed
		}
		y.SetBytes(b)

		if !c.solveForX(x,y) {	// Find a corresponding x-coordinate
			continue	// none, retry
		}

		// Pick a random sign for the x-coordinate
		b = b[0:1]
		rand.XORKeyStream(b,b)
		if c.coordSign(x) != uint(b[0] >> 7) {
			x.Neg(x)
		}

		if !c.onCurve(x,y) {
			panic("Pick generated a bad point")
		}

		return data[dl:]
	}
}

// Extract embedded data from a point group element,
// or an error if embedded data is invalid or not present.
func (c *curve) data(x,y *crypto.ModInt) ([]byte,error) {
	l := y.Len()
	b := y.Encode()
	dl := int(b[l-1])
	if dl > c.pickLen() {
		return nil,errors.New("invalid embedded data length")
	}
	return b[l-dl-1:l-1],nil
}

