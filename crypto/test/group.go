package test

import (
	"dissent/crypto"
)


// A generic benchmark suite for abstract groups.
type GroupBench struct {
	g crypto.Group

	// Random secrets and points for testing
	x,y crypto.Secret
	X,Y crypto.Point
	xe []byte	// encoded Secret
	Xe []byte	// encoded Point
}

func NewGroupBench(g crypto.Group) *GroupBench {
	var gb GroupBench
	gb.g = g
	gb.x = g.Secret().Pick(crypto.RandomStream)
	gb.y = g.Secret().Pick(crypto.RandomStream)
	gb.xe = gb.x.Encode()
	gb.X,_ = g.Point().Pick(nil, crypto.RandomStream)
	gb.Y,_ = g.Point().Pick(nil, crypto.RandomStream)
	gb.Xe = gb.X.Encode()
	return &gb
}


func (gb GroupBench) SecretAdd(iters int) {
	for i := 1; i < iters; i++ {
		gb.x.Add(gb.x,gb.y)
	}
}

func (gb GroupBench) SecretSub(iters int) {
	for i := 1; i < iters; i++ {
		gb.x.Sub(gb.x,gb.y)
	}
}

func (gb GroupBench) SecretNeg(iters int) {
	for i := 1; i < iters; i++ {
		gb.x.Neg(gb.x)
	}
}

func (gb GroupBench) SecretMul(iters int) {
	for i := 1; i < iters; i++ {
		gb.x.Mul(gb.x,gb.y)
	}
}

func (gb GroupBench) SecretDiv(iters int) {
	for i := 1; i < iters; i++ {
		gb.x.Div(gb.x,gb.y)
	}
}

func (gb GroupBench) SecretInv(iters int) {
	for i := 1; i < iters; i++ {
		gb.x.Inv(gb.x)
	}
}

func (gb GroupBench) SecretPick(iters int) {
	for i := 1; i < iters; i++ {
		gb.x.Pick(crypto.RandomStream)
	}
}

func (gb GroupBench) SecretEncode(iters int) {
	for i := 1; i < iters; i++ {
		gb.x.Encode()
	}
}

func (gb GroupBench) SecretDecode(iters int) {
	for i := 1; i < iters; i++ {
		gb.x.Decode(gb.xe)
	}
}


func (gb GroupBench) PointAdd(iters int) {
	for i := 1; i < iters; i++ {
		gb.X.Add(gb.X,gb.Y)
	}
}

func (gb GroupBench) PointSub(iters int) {
	for i := 1; i < iters; i++ {
		gb.X.Sub(gb.X,gb.Y)
	}
}

func (gb GroupBench) PointNeg(iters int) {
	for i := 1; i < iters; i++ {
		gb.X.Neg(gb.X)
	}
}

func (gb GroupBench) PointMul(iters int) {
	for i := 1; i < iters; i++ {
		gb.X.Mul(gb.X,gb.y)
	}
}

func (gb GroupBench) PointBaseMul(iters int) {
	for i := 1; i < iters; i++ {
		gb.X.Mul(nil,gb.y)
	}
}

func (gb GroupBench) PointPick(iters int) {
	for i := 1; i < iters; i++ {
		gb.X.Pick(nil, crypto.RandomStream)
	}
}

func (gb GroupBench) PointEncode(iters int) {
	for i := 1; i < iters; i++ {
		gb.X.Encode()
	}
}

func (gb GroupBench) PointDecode(iters int) {
	for i := 1; i < iters; i++ {
		gb.X.Decode(gb.Xe)
	}
}

