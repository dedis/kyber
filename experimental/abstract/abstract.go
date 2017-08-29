package abstract

import "github.com/dedis/kyber"

/*
Simple collection of interfaces to make old code work.
*/

type Suite interface {
	kyber.Group
}

type Point interface {
	kyber.Point
}

type Scalar interface {
	kyber.Scalar
}
