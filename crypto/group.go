package crypto

import (
	"bytes"
	"math/big"
	"crypto/cipher"
	"fmt"
	"time"
)

/*
A Secret abstractly represents a secret value by which
a Point (group element) may be encrypted to produce another Point.
This is an exponent in DSA-style groups,
in which security is based on the Discrete Logarithm assumption,
and a scalar multiplier in elliptic curve groups.
*/
type Secret interface {
	String() string

	// Equality test for two secrets derived from the same Group
	Equal(s2 Secret) bool

	// Set to the sum of secrets a and b
	Add(a,b Secret) Secret

	// Set to the modular negation of secret a
	Neg(a Secret) Secret

	// Set to a fresh random or pseudo-random secret
	Pick(rand cipher.Stream) Secret

	Encode() []byte
	Decode(buf []byte) Secret
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
	String() string
	Equal(s2 Point) bool

	Null() Point			// Set to neutral identity element
	Base() Point			// Set to well-known generator

	// Pick and set to a point that is at least partly [pseudo-]random,
	// and optionally so as to encode a limited amount of specified data.
	// If data is nil, the point is completely [pseudo]-random.
	// Returns this Point and a slice containing the remaining data
	// following the data that was successfully embedded in this point.
	// XXX also return Point for consistency & convenience
	Pick(data []byte,rand cipher.Stream) (Point, []byte)

	// Maximum number of bytes that can be reliably embedded
	// in a single group element via Pick().
	PickLen() int

	// Extract data embedded in a point chosen via Embed().
	// Returns an error if doesn't represent valid embedded data.
	Data() ([]byte,error)

	// Set to the encryption of point p with secret s
	Encrypt(p Point, s Secret) Point

	// Combine points so that their secrets add homomorphically
	Add(a,b Point) Point

	// Encode point into bytes
	Encode() []byte

	// Decode and validate a point
	Decode(buf []byte) (Point, error)
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

It is expected that any implementation of this interface
should satisfy suitable hardness assumptions for the applicable group:
e.g., that it is cryptographically hard for an adversary to
take an encrypted Point and the known generator it was based on,
and derive the Secret with which the Point was encrypted.
Any implementation is also expected to satisfy
the standard homomorphism properties that Diffie-Hellman
and the associated body of public-key cryptography are based on.
*/
type Group interface {

	SecretLen() int			// Max len of secrets in bytes
	Secret() Secret			// Create new secret

	PointLen() int			// Max len of point in bytes
	Point() Point			// Create new point

	Order() *big.Int		// Number of points in the group
	// (actually not sure we want GroupOrder() - may not be needed,
	// and may interfere with most efficent use of curve25519,
	// in which we might want to use both the curve and its twist...)
}

func testEmbed(g Group,s string) {
	println("embedding: ",s)
	b := []byte(s)

	p,rem := g.Point().Pick(b, RandomStream)
	println("embedded, remainder",len(rem),"/",len(b),":",string(rem))
	x,err := p.Data()
	if err != nil {
		panic("Point extraction failed: "+err.Error())
	}
	println("extracted data: ",string(x))

	if !bytes.Equal(append(x,rem...), b) {
		panic("Point embedding corrupted the data")
	}
}

// Apply a generic set of validation tests to a cryptographic Group.
func TestGroup(g Group) {
	fmt.Printf("\nTesting %d-bit group\n",g.Order().BitLen())

	// Do a simple Diffie-Hellman test
	s1 := g.Secret().Pick(RandomStream)
	s2 := g.Secret().Pick(RandomStream)
	println("s1 = ",s1.String())
	println("s2 = ",s2.String())
	if s1.Equal(s2) {
		panic("uh-oh, not getting unique secrets!")
	}

	gen := g.Point().Base()
	p1 := g.Point().Encrypt(gen,s1)
	p2 := g.Point().Encrypt(gen,s2)
	println("p1 = ",p1.String())
	println("p2 = ",p2.String())
	if p1.Equal(p2) {
		panic("uh-oh, encryption isn't producing unique points!")
	}

	dh1 := g.Point().Encrypt(p1,s2)
	dh2 := g.Point().Encrypt(p2,s1)
	if !dh1.Equal(dh2) {
		panic("Diffie-Hellman didn't work")
	}
	println("shared secret = ",dh1.String())

	// Test randomly picked points
	p1.Pick(nil, RandomStream)
	p2.Pick(nil, RandomStream)
	if p1.Equal(p2) {
		panic("Pick() not producing unique points")
	}
	println("random point = ",p1.String())
	println("random point = ",p2.String())

	// Test embedding data
	testEmbed(g,"Hi!")
	testEmbed(g,"The quick brown fox jumps over the lazy dog")
}

// A simple microbenchmark suite for abstract group functionality.
func BenchGroup(g Group) {

	// Point encryption
	s := g.Secret().Pick(RandomStream)
	p := g.Point()
	p.Pick(nil, RandomStream)
	beg := time.Now()
	iters := 500
	for i := 1; i < iters; i++ {
		p.Encrypt(p,s)
	}
	end := time.Now()
	fmt.Printf("EncryptPoint: %f ops/sec\n",
			float64(iters) / 
			(float64(end.Sub(beg)) / 1000000000.0))

	// Data embedding
	beg = time.Now()
	iters = 2000
	for i := 1; i < iters; i++ {
		p.Pick([]byte("abc"), RandomStream)
	}
	end = time.Now()
	fmt.Printf("PickPoint: %f ops/sec\n",
			float64(iters) / 
			(float64(end.Sub(beg)) / 1000000000.0))

	// Secret addition (in-place arithmetic)
	s2 := g.Secret().Pick(RandomStream)
	beg = time.Now()
	iters = 1000000
	for i := 1; i < iters; i++ {
		s.Add(s,s2)
	}
	end = time.Now()
	fmt.Printf("Secret.Add: %f ops/sec\n",
			float64(iters) / 
			(float64(end.Sub(beg)) / 1000000000.0))

	println()
}

