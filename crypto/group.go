package crypto

import (
	"bytes"
	"math/big"
	"crypto/cipher"
	"fmt"
)

type Secret interface {
	Encode() []byte
	Decode(buf []byte) Secret
	String() string
	Equal(s2 Secret) bool
}

type Point interface {
	Encode() []byte
	Decode(buf []byte) Point
	String() string
	Equal(s2 Point) bool
}


type Group interface {

	SecretLen() int			// Max len of secrets in bytes
	RandomSecret(rand cipher.Stream) Secret // Pick a [pseudo]random secret
	AddSecret(x, y Secret) Secret // Combine two secrets commutatively
	GroupOrder() *big.Int		// Number of points in the group
	// (actually not sure we want GroupOrder() - may not be needed,
	// and may interfere with most efficent use of curve25519,
	// in which we might want to use both the curve and its twist...)

	PointLen() int			// Max len of point in bytes
	ValidPoint(p Point) bool	// Test if a point is valid (in-group)
	IdentityPoint() Point		// The identity group element
	BasePoint() Point		// Well-known base point
	RandomPoint(rand cipher.Stream) Point // [Pseudo]random base point

	// Pick a point in this group at least partly [pseudo-]randomly,
	// and optionally so as to encode a limited amount of specified data.
	// If data is empty, the point is completely [pseudo]-random.
	// Returns the chosen point and a slice containing the remaining data
	// following the data that was successfully embedded in this point.
	EmbedPoint(data []byte,rand cipher.Stream) (Point,[]byte)

	// Maximum number of bytes that can be reliably embedded
	// in a single group element via EmbedPoint().
	EmbedLen() int

	// Extract data embedded in a point chosen via Embed().
	// Returns an error if doesn't represent valid embedded data.
	Extract(p Point) ([]byte,error)

	EncryptPoint(p Point, s Secret) Point

	EncodePoint(p Point) []byte		// Encode point into bytes
	DecodePoint(buf []byte) (Point,error)	// Decode and validate a point

}

func concat(a,b []byte) []byte {
	d := make([]byte,len(a)+len(b))
	copy(d,a)
	copy(d[len(a):],b)
	return d
}

func testEmbed(g Group,s string) {
	println("embedding: ",s)
	b := []byte(s)

	p,rem := g.EmbedPoint(b, RandomStream)
	if !g.ValidPoint(p) {
		panic("EmbedPoint producing invalid point")
	}
	println("embedded, remainder",len(rem),"/",len(b),":",string(rem))
	x,err := g.Extract(p)
	if err != nil {
		panic("Point extraction failed: "+err.Error())
	}
	println("extracted data: ",string(x))

	if !bytes.Equal(concat(x,rem), b) {
		panic("Point embedding corrupted the data")
	}
}

func TestGroup(g Group) {
	fmt.Printf("\nTesting %d-bit group\n",g.GroupOrder().BitLen())

	if !g.ValidPoint(g.BasePoint()) {
		panic("Generator isn't a valid point!?")
	}

	// Do a simple Diffie-Hellman test
	s1 := g.RandomSecret(RandomStream)
	s2 := g.RandomSecret(RandomStream)
	println("s1 = ",s1.String())
	println("s2 = ",s2.String())
	if s1.Equal(s2) {
		panic("uh-oh, not getting unique secrets!")
	}

	p1 := g.EncryptPoint(g.BasePoint(),s1)
	p2 := g.EncryptPoint(g.BasePoint(),s2)
	println("p1 = ",p1.String())
	println("p2 = ",p2.String())
	if !g.ValidPoint(p1) || !g.ValidPoint(p2) {
		panic("EncryptPoint is producing invalid points")
	}
	if p1.Equal(p2) {
		panic("uh-oh, encryption isn't producing unique points!")
	}

	dh1 := g.EncryptPoint(p1,s2)
	dh2 := g.EncryptPoint(p2,s1)
	println("dh1 = ",dh1.String())
	println("dh2 = ",dh2.String())
	if !g.ValidPoint(dh1) || !g.ValidPoint(dh2) {
		panic("Diffie-Hellman yielded invalid point")
	}
	if !dh1.Equal(dh2) {
		panic("Diffie-Hellman didn't work")
	}
	println("shared secret = ",dh1.String())

	// Test random points
	r1 := g.RandomPoint(RandomStream)
	r2 := g.RandomPoint(RandomStream)
	if !g.ValidPoint(r1) || !g.ValidPoint(r2) {
		panic("RandomPoint produced invalid point")
	}
	if r1.Equal(r2) {
		panic("RandomPoint not producing unique points")
	}
	println("random point = ",r1.String())
	println("random point = ",r2.String())

	// Test embedding data
	testEmbed(g,"Hi!")
	testEmbed(g,"The quick brown fox jumps over the lazy dog")
}

