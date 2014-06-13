package crypto

import (
	"bytes"
	"math/big"
	"crypto/cipher"
	"fmt"
	"time"
)

type Secret interface {
	String() string

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

type Point interface {
	String() string
	Equal(s2 Point) bool

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

