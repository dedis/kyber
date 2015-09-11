package abstract

import (
	"crypto/cipher"
)

// XXX consider renaming Secret to Scalar?

/*
Element is the abstract interface to an algebraic group or field element,
supporting the algebraic operations typically used in
standard public-key crypto.
Not every instance of Element will necessarily support all operations,
and supported operations will expect Element operands to be of
specific, appropriate Element types:
the caller must know a particular Element type's usage constraints,
and unsupported or incorrectly-used operations will simply panic.
The struct types Secret and Point offer slightly higher-level,
more purpose-specific "front-end" encapsulations for Element.
*/
type Element interface {
	// Any Element has some "native" marshaled encoding
	Marshaling

	// Create a new uninitialized element of the same type
	New() Element

	// Set equal to another Element a
	Set(a Element)

	// Equality test for two Elements of the same type
	Equal(a Element) bool

	// Set to the additive identity (0)
	Zero()

	// Set to the sum of elements a and b
	Add(a, b Element)

	// Set to the difference a - b
	Sub(a, b Element)

	// Set to the additive negation of element a
	Neg(a Element)

	// Set to the multiplicative identity (1)
	One()

	// Set to the product of elements a and b.
	// For elements of additive groups,
	// this operation represents scalar multiplication,
	// in which case a is the integer scalar and b is the base element;
	// b can be nil to request the standard base.
	Mul(a, b Element)

	// Set to a fresh [pseudo-]random element,
	// optionally so as to embed given data.
	// A given Element type supports embedding a limited
	// number of data bytes, possibly zero.
	// Returns any remainding data bytes not embedded.
	Pick(data []byte, rand cipher.Stream) []byte

	// Return the maximum number of bytes that can always be embedded
	// in a single group element via Pick().
	// If a Pick call is supplied with more data than this,
	// it may embed anywhere between PickLen and all supplied bytes,
	// perhaps nondeterministically based on the supplied randomness.
	// Returns 0 if this Element type does not support data embedding.
	PickLen() int

	// Extract data embedded in an Element chosen via Pick().
	// Returns an error if the Element contains no valid embedded data,
	// but this error condition is not guaranteed to be detected
	// for Elements Picked with data == nil.
	Data() ([]byte, error)
}

type FieldElement interface {
	Element

	// Set to a small integer value
	// XXX maybe this could/should be in Element?
	SetInt64(v int64)

	// Set to the division of element a by element b
	Div(a, b Element)

	// Set to the multiplicative inverse of element a
	Inv(a Element)
}


// Generic, default implementations of some Element operations.
// XXX perhaps should be elsewhere in a sub-package,
// since they're only used by Element implementors?
// (And perhaps the Element interface belongs there too?)

func Sub(dst, a, b Element) {
	c := b.New()
	c.Neg(b)
	dst.Add(a, c)
}

func Div(dst, a, b FieldElement) {
	c := b.New().(FieldElement)
	c.Inv(b)
	dst.Div(a, c)
}


/*
A Secret abstractly represents a secret value by which
a Point (group element) may be encrypted to produce another Point.
This is an exponent in DSA-style groups,
in which security is based on the Discrete Logarithm assumption,
and a scalar multiplier in elliptic curve groups.
XXX probably rename to Scalar.
*/
type Secret struct {
	FieldElement
}

// Equality test for two Secrets derived from the same Group
func (s Secret) Equal(s2 Secret) bool {
	return s.FieldElement.Equal(s2.FieldElement)
}

// Set equal to another Secret a and return this Secret.
func (s Secret) Set(a Secret) Secret {
	s.FieldElement.Set(a.FieldElement)
	return s
}

// Set to a small integer value and return this Secret.
func (s Secret) SetInt64(v int64) Secret {
	s.FieldElement.SetInt64(v)
	return s
}

// Set to the additive identity (0)
func (s Secret) Zero() Secret {
	s.FieldElement.Zero()
	return s
}

// Set to the modular sum of secrets a and b
func (s Secret) Add(a, b Secret) Secret {
	s.FieldElement.Add(a.FieldElement, b.FieldElement)
	return s
}

// Set to the modular difference a - b
func (s Secret) Sub(a, b Secret) Secret {
	s.FieldElement.Sub(a.FieldElement, b.FieldElement)
	return s
}

// Set to the modular negation of secret a
func (s Secret) Neg(a Secret) Secret {
	s.FieldElement.Neg(a.FieldElement)
	return s
}

// Set to the multiplicative identity (1)
func (s Secret) One() Secret {
	s.FieldElement.One()
	return s
}

// Set to the modular product of secrets a and b
func (s Secret) Mul(a, b Secret) Secret {
	s.FieldElement.Mul(a.FieldElement, b.FieldElement)
	return s
}

// Set to the modular division of secret a by secret b
func (s Secret) Div(a, b Secret) Secret {
	s.FieldElement.Div(a.FieldElement, b.FieldElement)
	return s
}

// Set to the modular inverse of secret a
func (s Secret) Inv(a Secret) Secret {
	s.FieldElement.Inv(a.FieldElement)
	return s
}

// Set to a fresh random or pseudo-random secret
// XXX add data parameter for consistency/generality
func (s Secret) Pick(rand cipher.Stream) Secret {
	s.FieldElement.Pick(nil, rand)
	return s
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
	Element
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
// XXX swap argument order for consistency with additive notation.
func (p Point) Mul(b Point, s Secret) Point {
	p.Element.Mul(s.FieldElement, b.Element)
	return p
}

// Set to the standard base point multiplied by scalar s.
// XXX also support alternate optimized, precomputed base points somehow.
func (p Point) BaseMul(s Secret) Point {
	p.Element.Mul(s.FieldElement, nil)
	return p
}


/*
This interface represents an abstract cryptographic group
usable for Diffie-Hellman key exchange, ElGamal encryption,
and the related body of public-key cryptographic algorithms
and zero-knowledge proof methods.
The Group interface is designed in particular to be a generic front-end
to both traditional DSA-style modular arithmetic groups
and ECDSA-style elliptic curves:
the caller of this interface's methods
need not know or care which specific mathematical construction
underlies the interface.

The Group interface is essentially just a "constructor" interface
enabling the caller to generate the two particular types of objects
relevant to DSA-style public-key cryptography;
we call these objects Points and Secrets.
The caller must explicitly initialize or set a new Point or Secret object
to some value before using it as an input to some other operation
involving Point and/or Secret objects.
For example, to compare a point P against the neutral (identity) element,
you might use P.Equal(suite.Point().Null()),
but not just P.Equal(suite.Point()).

It is expected that any implementation of this interface
should satisfy suitable hardness assumptions for the applicable group:
e.g., that it is cryptographically hard for an adversary to
take an encrypted Point and the known generator it was based on,
and derive the Secret with which the Point was encrypted.
Any implementation is also expected to satisfy
the standard homomorphism properties that Diffie-Hellman
and the associated body of public-key cryptography are based on.

XXX should probably delete the somewhat redundant ...Len() methods.
*/
type Group interface {
	String() string

	SecretLen() int // Max len of secrets in bytes
	Secret() Secret // Create new secret

	PointLen() int // Max len of point in bytes
	Point() Point  // Create new point

	PrimeOrder() bool // Returns true if group is prime-order
}
