package abstract

import (
	"crypto/cipher"
)

/*
A Scalar abstractly represents a scalar value by which
a Point (group element) may be encrypted to produce another Point.
This is an exponent in DSA-style groups,
in which security is based on the Discrete Logarithm assumption,
and a scalar multiplier in elliptic curve groups.
*/
type Scalar interface {
	Marshaling

	// Equality test for two Scalars derived from the same Group
	Equal(s2 Scalar) bool

	// Set equal to another Scalar a
	Set(a Scalar) Scalar

	// Clone creates a new Scalar with same value
	Clone() Scalar

	// Set to a small integer value
	SetInt64(v int64) Scalar

	// Set to the additive identity (0)
	Zero() Scalar

	// Set to the modular sum of scalars a and b
	Add(a, b Scalar) Scalar

	// Set to the modular difference a - b
	Sub(a, b Scalar) Scalar

	// Set to the modular negation of scalar a
	Neg(a Scalar) Scalar

	// Set to the multiplicative identity (1)
	One() Scalar

	// Set to the modular product of scalars a and b
	Mul(a, b Scalar) Scalar

	// Set to the modular division of scalar a by scalar b
	Div(a, b Scalar) Scalar

	// Set to the modular inverse of scalar a
	Inv(a Scalar) Scalar

	// Set to a fresh random or pseudo-random scalar
	Pick(rand cipher.Stream) Scalar
	// SetBytes will take bytes and create a scalar out of it
	SetBytes([]byte) Scalar

	// Bytes returns the raw internal representation
	Bytes() []byte
}

/*
A Point abstractly represents an element of a public-key cryptographic Group.
For example,
this is a number modulo the prime P in a DSA-style Schnorr group,
or an x,y point on an elliptic curve.
A Point can contain a Diffie-Hellman public key,
an ElGamal ciphertext, etc.
*/
type Point interface {
	Marshaling

	// Equality test for two Points derived from the same Group
	Equal(s2 Point) bool

	Null() Point // Set to neutral identity element

	// Set to this group's standard base point.
	Base() Point

	// Pick and set to a point that is at least partly [pseudo-]random,
	// and optionally so as to encode a limited amount of specified data.
	// If data is nil, the point is completely [pseudo]-random.
	// Returns this Point and a slice containing the remaining data
	// following the data that was successfully embedded in this point.
	Pick(data []byte, rand cipher.Stream) (Point, []byte)

	// Maximum number of bytes that can be reliably embedded
	// in a single group element via Pick().
	PickLen() int

	// Set equal to another Point p.
	Set(p Point) Point

	// Clone clones the underlying point.
	Clone() Point

	// Extract data embedded in a point chosen via Embed().
	// Returns an error if doesn't represent valid embedded data.
	Data() ([]byte, error)

	// Add points so that their scalars add homomorphically
	Add(a, b Point) Point

	// Subtract points so that their scalars subtract homomorphically
	Sub(a, b Point) Point

	// Set to the negation of point a
	Neg(a Point) Point

	// Encrypt point p by multiplying with scalar s.
	// If p == nil, encrypt the standard base point Base().
	Mul(p Point, s Scalar) Point
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
we call these objects Points and Scalars.
The caller must explicitly initialize or set a new Point or Scalar object
to some value before using it as an input to some other operation
involving Point and/or Scalar objects.
For example, to compare a point P against the neutral (identity) element,
you might use P.Equal(suite.Point().Null()),
but not just P.Equal(suite.Point()).

It is expected that any implementation of this interface
should satisfy suitable hardness assumptions for the applicable group:
e.g., that it is cryptographically hard for an adversary to
take an encrypted Point and the known generator it was based on,
and derive the Scalar with which the Point was encrypted.
Any implementation is also expected to satisfy
the standard homomorphism properties that Diffie-Hellman
and the associated body of public-key cryptography are based on.

XXX should probably delete the somewhat redundant ...Len() methods.
*/
type Group interface {
	String() string

	ScalarLen() int // Max len of scalars in bytes
	Scalar() Scalar // Create new scalar

	PointLen() int // Max len of point in bytes
	Point() Point  // Create new point

	PrimeOrder() bool // Returns true if group is prime-order
}
