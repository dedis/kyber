package abstract

import (
	"io"
	"crypto/cipher"
	"github.com/dedis/crypto/group"
	"golang.org/x/net/context"
)

/*
A Scalar abstractly represents a secret value by which
a Point (group element) may be encrypted to produce another Point.
This is an exponent in DSA-style groups,
in which security is based on the Discrete Logarithm assumption,
and a scalar multiplier in elliptic curve groups.
XXX probably rename to Scalar.
*/
type Scalar struct {
	group.FieldElement
}

// Equality test for two Scalars derived from the same Group
func (s Scalar) Equal(s2 Scalar) bool {
	return s.FieldElement.Equal(s2.FieldElement)
}

// Set equal to another Scalar a and return this Scalar.
func (s Scalar) Set(a Scalar) Scalar {
	s.FieldElement.Set(a.FieldElement)
	return s
}

// Set to a small integer value and return this Scalar.
func (s Scalar) SetInt64(v int64) Scalar {
	s.FieldElement.SetInt64(v)
	return s
}

// Set to the additive identity (0)
func (s Scalar) Zero() Scalar {
	s.FieldElement.Zero()
	return s
}

// Set to the modular sum of secrets a and b
func (s Scalar) Add(a, b Scalar) Scalar {
	s.FieldElement.Add(a.FieldElement, b.FieldElement)
	return s
}

// Set to the modular difference a - b
func (s Scalar) Sub(a, b Scalar) Scalar {
	s.FieldElement.Sub(a.FieldElement, b.FieldElement)
	return s
}

// Set to the modular negation of secret a
func (s Scalar) Neg(a Scalar) Scalar {
	s.FieldElement.Neg(a.FieldElement)
	return s
}

// Set to the multiplicative identity (1)
func (s Scalar) One() Scalar {
	s.FieldElement.One()
	return s
}

// Set to the modular product of secrets a and b
func (s Scalar) Mul(a, b Scalar) Scalar {
	s.FieldElement.Mul(a.FieldElement, b.FieldElement)
	return s
}

// Set to the modular division of secret a by secret b
func (s Scalar) Div(a, b Scalar) Scalar {
	s.FieldElement.Div(a.FieldElement, b.FieldElement)
	return s
}

// Set to the modular inverse of secret a
func (s Scalar) Inv(a Scalar) Scalar {
	s.FieldElement.Inv(a.FieldElement)
	return s
}

// Set to a fresh random or pseudo-random secret
func (s Scalar) Pick(data []byte, rand cipher.Stream) Scalar {
	s.FieldElement.Pick(data, rand)
	return s
}

// Return true if this Scalar contains no FieldElement object
func (s Scalar) Nil() bool {
	return s.FieldElement == nil
}

// Return encoded length of this Point in bytes.
func (s Scalar) MarshalSize() int {
	return s.FieldElement.MarshalSize()
}

// Encode the contents of this Point and write it to an io.Writer.
func (s Scalar) Marshal(ctx context.Context, w io.Writer) (int, error) {
	return s.FieldElement.Marshal(ctx, w)
}

// Unmarshal a Scalar from a given Reader,
// creating an appropriate FieldElement instance if necessary.
func (s *Scalar) Unmarshal(ctx context.Context, r io.Reader) (int, error) {
	if s.FieldElement == nil {
		s.FieldElement = group.Get(ctx).Scalar()
	}
	return s.FieldElement.Unmarshal(ctx, r)
}


/*
A Point abstractly represents an element of a public-key cryptographic Group.
For example,
this is a number modulo the prime P in a DSA-style Schnorr group,
or an x,y point on an elliptic curve.
A Point can contain a Diffie-Hellman public key,
an ElGamal ciphertext, etc.
*/
type Point struct {
	group.Element
}

// Equality test for two Points derived from the same Group
func (p Point) Equal(s2 Point) bool {
	return p.Element.Equal(s2.Element)
}

// Set to neutral identity element
// XXX rename to Zero for consistency?
func (p Point) Null() Point {
	p.Element.Zero()
	return p
}

// Set to this group's standard base point.
// XXX rename to One for consistency?
func (p Point) Base() Point {
	p.Element.One()
	return p
}

// Pick and set to a point that is at least partly [pseudo-]random,
// and optionally so as to encode a limited amount of specified data.
// If data is nil, the point is completely [pseudo]-random.
// Returns this Point and a slice containing the remaining data
// following the data that was successfully embedded in this point.
func (p Point) Pick(data []byte, rand cipher.Stream) (Point, []byte) {
	rem := p.Element.Pick(data, rand)
	return p, rem
}

// Add points so that their secrets add homomorphically
func (p Point) Add(a, b Point) Point {
	p.Element.Add(a.Element, b.Element)
	return p
}

// Subtract points so that their secrets subtract homomorphically
func (p Point) Sub(a, b Point) Point {
	p.Element.Sub(a.Element, b.Element)
	return p
}

// Set to the negation of point a
func (p Point) Neg(a Point) Point {
	p.Element.Neg(a.Element)
	return p
}

// Encrypt point p by multiplying with secret s.
func (p Point) Mul(b Point, s Scalar) Point {
	p.Element.Mul(b.Element, s.FieldElement)
	return p
}

// Set to the standard base point multiplied by scalar s.
// XXX also support alternate optimized, precomputed base points somehow.
func (p Point) BaseMul(s Scalar) Point {
	p.Element.Mul(nil, s.FieldElement)
	return p
}

// Return true if this Point contains no Element object
func (p Point) Nil() bool {
	return p.Element == nil
}

// Return encoded length of this Point in bytes.
func (p Point) MarshalSize() int {
	return p.Element.MarshalSize()
}

// Encode the contents of this Point and write it to an io.Writer.
func (p Point) Marshal(ctx context.Context, w io.Writer) (int, error) {
	return p.Element.Marshal(ctx, w)
}

// Unmarshal a Point from a given Reader,
// creating an appropriate Element instance if necessary.
func (p *Point) Unmarshal(ctx context.Context, r io.Reader) (int, error) {
	if p.Element == nil {
		p.Element = group.Get(ctx).Element()
	}
	return p.Element.Unmarshal(ctx, r)
}

