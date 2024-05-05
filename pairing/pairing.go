package pairing

import "go.dedis.ch/kyber/v3"

// Suite interface represents a triplet of elliptic curve groups (G₁, G₂
// and GT) such that there exists a function e(g₁ˣ,g₂ʸ)=gTˣʸ (where gₓ is a
// generator of the respective group) which is called a pairing.
type Suite interface {
	G1() kyber.Group
	G2() kyber.Group
	GT() kyber.Group
	Pair(p1, p2 kyber.Point) kyber.Point
	// ValidatePairing is a simpler way to verify a pairing equation.
	// e(p1,p2) =?= e(inv1^-1, inv2^-1)
	ValidatePairing(p1, p2, inv1, inv2 kyber.Point) bool
	kyber.Encoding
	kyber.HashFactory
	kyber.XOFFactory
	kyber.Random
}
