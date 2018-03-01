package pairing

import "github.com/dedis/kyber"

// Suite ...
type Suite interface {
	G1() kyber.Group
	G2() kyber.Group
	GT() kyber.Group
	Pair(p1, p2 kyber.Point) kyber.Point
	kyber.Encoding
	kyber.HashFactory
	kyber.XOFFactory
	kyber.Random
}
