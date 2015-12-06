package group

/*
The Group interface represents an abstract cryptographic group
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

XXX delete the somewhat redundant ...Len() methods?
*/
type Group interface {
	String() string // Return human-readable name of group

	ElementLen() int  // Length of encoded group element in bytes
	Element() Element // Create new group element

	ScalarLen() int       // Length of encoded scalar in bytes
	Scalar() FieldElement // Create new scalar modulo the group order

	PrimeOrder() bool // Returns true if group is prime-order
}
