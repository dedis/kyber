package group

import (
	"crypto/cipher"
	"github.com/dedis/crypto/marshal"
)

/*
Element is the abstract interface to an algebraic group element,
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
	marshal.Marshaling

	// Create a new uninitialized element of the same type
	New() Element

	// Set equal to another Element a
	Set(a Element) Element

	// Equality test for two Elements of the same type
	Equal(a Element) bool

	// Set to the additive identity (0)
	Zero() Element

	// Set to the sum of elements a and b
	Add(a, b Element) Element

	// Set to the difference a - b
	Sub(a, b Element) Element

	// Set to the additive negation of element a
	Neg(a Element) Element

	// Set to the multiplicative identity (1)
	One() Element

	// Set to the product of elements a and b.
	// For elements of additive groups,
	// this operation represents scalar multiplication,
	// in which case a is the generator and b is the integer scalar;
	// a can be nil to request the standard base.
	Mul(a, b Element) Element

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
	SetInt64(v int64) FieldElement

	// Set to the division of element a by element b
	Div(a, b Element) FieldElement

	// Set to the multiplicative inverse of element a
	Inv(a Element) FieldElement
}

// Default, not necessarily highly efficient implementation of element.Sub
// by negating argument b then adding.
func Sub(dst, a, b Element) {
	c := b.New()
	c.Neg(b)
	dst.Add(a, c)
}

// Default, not necessarily highly efficient implementation of element.Div
// by inverting argument b then multiplying.
func Div(dst, a, b FieldElement) {
	c := b.New().(FieldElement)
	c.Inv(b)
	dst.Mul(a, c)
}
