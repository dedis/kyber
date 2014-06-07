package main

import (
	"math/big"
	"crypto/cipher"
)

type Secret struct {
	big.Int 
}

func (s *Secret) Encode() []byte { return s.Bytes() }
func (s *Secret) Decode(buf []byte) *Secret {
	s.SetBytes(buf)
	return s
}

type Point struct {
	big.Int 
}

func (p *Point) Encode() []byte { return p.Bytes() }
func (p *Point) Decode(buf []byte) *Point {
	p.SetBytes(buf)
	return p
}


type Group interface {

	SecretLen() int			// Max len of secrets in bytes
	RandomSecret(rand cipher.Stream) *Secret // Pick a [pseudo]random secret
	AddSecret(x, y *Secret) *Secret // Combine two secrets commutatively
	GroupOrder() *big.Int		// Number of points in the group
	// (actually not sure we want GroupOrder() - may not be needed,
	// and may interfere with most efficent use of curve25519,
	// in which we might want to use both the curve and its twist...)

	PointLen() int			// Max len of point in bytes
	IdentityPoint() *Point		// The identity group element
	BasePoint() *Point		// Well-known base point
	RandomPoint(rand cipher.Stream) *Point	// [Pseudo]random base point
	ValidPoint(p *Point) bool	// Test if a point is valid (in-group)

	EncryptPoint(p *Point, s *Secret) *Point

	EncodePoint(p *Point) []byte		// Encode point into bytes
	DecodePoint(buf []byte) (*Point,error)	// Decode and validate a point


	// Minimum number of bytes that can always
	// (or with overwhelming probability)
	// be embedded into a single group element.
//	EmbedMinLen() int

	// Embed a potentially variable number of bytes in a group element.
	// Returns element and number of prefix bytes successfully embedded.
	// If len > EmbedMinLen(), may embed less than full data slice
//	EmbedPoint(data []byte) (Point, int)

	// Embed a variable number of bytes to form a series of elements.
//	EmbedBytes(data []byte) []Point

}


func TestGroup(g Group) {

	if !g.ValidPoint(g.BasePoint()) {
		panic("Generator isn't a valid point!?")
	}

	// Do a simple Diffie-Hellman test
	s1 := g.RandomSecret(RandomStream)
	s2 := g.RandomSecret(RandomStream)
	println("s1 = ",s1.String())
	println("s2 = ",s2.String())
	if s1.Cmp(&s2.Int) == 0 {
		panic("uh-oh, not getting unique secrets!")
	}

	p1 := g.EncryptPoint(g.BasePoint(),s1)
	p2 := g.EncryptPoint(g.BasePoint(),s2)
	println("p1 = ",p1.String())
	println("p2 = ",p2.String())
	if !g.ValidPoint(p1) || !g.ValidPoint(p2) {
		panic("EncryptPoint is producing invalid points")
	}
	if p1.Cmp(&p2.Int) == 0 {
		panic("uh-oh, encryption isn't producing unique points!")
	}

	dh1 := g.EncryptPoint(p1,s2)
	dh2 := g.EncryptPoint(p2,s1)
	println("dh1 = ",dh1.String())
	println("dh2 = ",dh2.String())
	if !g.ValidPoint(dh1) || !g.ValidPoint(dh2) {
		panic("Diffie-Hellman yielded invalid point")
	}
	if dh1.Cmp(&dh2.Int) != 0 {
		panic("Diffie-Hellman didn't work")
	}
	println("shared secret = ",dh1.String())

	// Check identity point and group order
	if g.EncryptPoint(g.IdentityPoint(),s1).Cmp(&g.IdentityPoint().Int) != 0 {
		panic("IdentityPoint doesn't act as an identity")
	}
	so := new(Secret)
	so.Int.Set(g.GroupOrder())
	if g.EncryptPoint(p1,so).Cmp(&g.IdentityPoint().Int) != 0 {
		panic("GroupOrder doesn't work")
	}

	// Test random points
	r1 := g.RandomPoint(RandomStream)
	r2 := g.RandomPoint(RandomStream)
	if !g.ValidPoint(r1) || !g.ValidPoint(r2) {
		panic("RandomPoint produced invalid point")
	}
	if r1.Cmp(&r2.Int) == 0 {
		panic("RandomPoint not producing unique points")
	}
}

