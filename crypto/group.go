package crypto

import (
	"bytes"
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

XXX rename Secret to Scalar?
*/
type Secret interface {
	String() string
	Encoding

	// Equality test for two Secrets derived from the same Group
	Equal(s2 Secret) bool

	// Set equal to another Secret a
	Set(a Secret) Secret

	// Set to a small integer value
	SetInt64(v int64) Secret

	// Set to the additive identity (0)
	Zero() Secret

	// Set to the modular sum of secrets a and b
	Add(a,b Secret) Secret

	// Set to the modular difference a - b
	Sub(a,b Secret) Secret

	// Set to the modular negation of secret a
	Neg(a Secret) Secret

	// Set to the multiplicative identity (1)
	One() Secret

	// Set to the modular product of secrets a and b
	Mul(a,b Secret) Secret

	// Set to the modular division of secret a by secret b
	Div(a,b Secret) Secret

	// Set to the modular inverse of secret a
	Inv(a Secret) Secret

	// Set to a fresh random or pseudo-random secret
	Pick(rand cipher.Stream) Secret
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
	Encoding

	// Equality test for two Points derived from the same Group
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

	// Add points so that their secrets add homomorphically
	Add(a,b Point) Point

	// Subtract points so that their secrets subtract homomorphically
	Sub(a,b Point) Point

	// Encrypt point p by multiplying with secret s.
	// If p == nil, encrypt the standard base point Base().
	Mul(p Point, s Secret) Point
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
	String() string

	SecretLen() int			// Max len of secrets in bytes
	Secret() Secret			// Create new secret

	PointLen() int			// Max len of point in bytes
	Point() Point			// Create new point
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
	fmt.Printf("\nTesting group '%s': %d-byte Point, %d-byte Secret\n",
			g.String(), g.PointLen(), g.SecretLen())

	// Do a simple Diffie-Hellman test
	s1 := g.Secret().Pick(RandomStream)
	s2 := g.Secret().Pick(RandomStream)
	println("s1 = ",s1.String())
	println("s2 = ",s2.String())
	if s1.Equal(s2) {
		panic("uh-oh, not getting unique secrets!")
	}

	gen := g.Point().Base()
	p1 := g.Point().Mul(gen,s1)
	p2 := g.Point().Mul(gen,s2)
	println("p1 = ",p1.String())
	println("p2 = ",p2.String())
	if p1.Equal(p2) {
		panic("uh-oh, encryption isn't producing unique points!")
	}

	dh1 := g.Point().Mul(p1,s2)
	dh2 := g.Point().Mul(p2,s1)
	if !dh1.Equal(dh2) {
		panic("Diffie-Hellman didn't work")
	}
	println("shared secret = ",dh1.String())

	// Test secret inverse to get from dh1 back to p1
	ptmp := g.Point().Mul(dh1, g.Secret().Inv(s2))
	if !ptmp.Equal(p1) {
		panic("Secret inverse didn't work")
	}

	// Zero and One identity secrets
	//println("dh1^0 = ",ptmp.Mul(dh1, g.Secret().Zero()).String())
	if !ptmp.Mul(dh1, g.Secret().Zero()).Equal(g.Point().Null()) {
		panic("Encryption with secret=0 didn't work")
	}
	if !ptmp.Mul(dh1, g.Secret().One()).Equal(dh1) {
		panic("Encryption with secret=1 didn't work")
	}

	// Additive homomorphic identities
	ptmp.Add(p1,p2)
	stmp := g.Secret().Add(s1,s2)
	pt2 := g.Point().Mul(gen,stmp)
	if !pt2.Equal(ptmp) {
		panic("Additive homomorphism doesn't work")
	}
	ptmp.Sub(p1,p2)
	stmp.Sub(s1,s2)
	pt2.Mul(gen,stmp)
	if !pt2.Equal(ptmp) {
		panic("Additive homomorphism doesn't work")
	}
	st2 := g.Secret().Neg(s2)
	st2.Add(s1,st2)
	if !stmp.Equal(st2) {
		panic("Secret.Neg doesn't work")
	}

	// Multiplicative homomorphic identities
	stmp.Mul(s1,s2)
	if !ptmp.Mul(gen,stmp).Equal(dh1) {
		panic("Multiplicative homomorphism doesn't work")
	}
	st2.Inv(s2)
	st2.Mul(st2,stmp)
	if !st2.Equal(s1) {
		panic("Secret division doesn't work")
	}
	st2.Div(stmp,s2)
	if !st2.Equal(s1) {
		panic("Secret division doesn't work")
	}

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

	// Test verifiable secret sharing
	testSharing(g)
}

// A simple microbenchmark suite for abstract group functionality.
func BenchGroup(g Group) {

	// Point addition
	b := g.Point().Base()
	p := g.Point()
	p.Pick(nil, RandomStream)
	beg := time.Now()
	iters := 10000
	for i := 1; i < iters; i++ {
		p.Add(p,b)
	}
	end := time.Now()
	fmt.Printf("Point.Add: %f ops/sec\n",
			float64(iters) / 
			(float64(end.Sub(beg)) / 1000000000.0))

	// Point encryption
	s := g.Secret().Pick(RandomStream)
	beg = time.Now()
	iters = 500
	for i := 1; i < iters; i++ {
		p.Mul(p,s)
	}
	end = time.Now()
	fmt.Printf("Point.Mul: %f ops/sec\n",
			float64(iters) / 
			(float64(end.Sub(beg)) / 1000000000.0))

	// Data embedding
	beg = time.Now()
	iters = 2000
	for i := 1; i < iters; i++ {
		p.Pick([]byte("abc"), RandomStream)
	}
	end = time.Now()
	fmt.Printf("Point.Pick: %f ops/sec\n",
			float64(iters) / 
			(float64(end.Sub(beg)) / 1000000000.0))

	// Secret addition (in-place arithmetic)
	s2 := g.Secret().Pick(RandomStream)
	beg = time.Now()
	iters = 10000000
	for i := 1; i < iters; i++ {
		s.Add(s,s2)
	}
	end = time.Now()
	fmt.Printf("Secret.Add: %f ops/sec\n",
			float64(iters) / 
			(float64(end.Sub(beg)) / 1000000000.0))

	// Secret multiplication
	beg = time.Now()
	iters = 1000000
	for i := 1; i < iters; i++ {
		s.Mul(s,s2)
	}
	end = time.Now()
	fmt.Printf("Secret.Mul: %f ops/sec\n",
			float64(iters) / 
			(float64(end.Sub(beg)) / 1000000000.0))

	// Secret inversion
	beg = time.Now()
	iters = 10000
	for i := 1; i < iters; i++ {
		s.Inv(s)
	}
	end = time.Now()
	fmt.Printf("Secret.Inv: %f ops/sec\n",
			float64(iters) / 
			(float64(end.Sub(beg)) / 1000000000.0))

	println()
}

