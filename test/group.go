package test

import (
	"github.com/dedis/crypto/abstract"
)

// A generic benchmark suite for abstract groups.
type GroupBench struct {
	// Random secrets and points for testing
	x, y abstract.Scalar
	X, Y abstract.Point
	xe   []byte // encoded Scalar
	Xe   []byte // encoded Point
}

func NewGroupBench(suite *abstract.Suite) *GroupBench {
	var gb GroupBench
	gb.x = suite.Scalar().Fresh()
	gb.y = suite.Scalar().Fresh()
	gb.xe, _ = gb.x.MarshalBinary()
	gb.X = suite.Point().Fresh()
	gb.Y = suite.Point().Fresh()
	gb.Xe, _ = gb.X.MarshalBinary()
	return &gb
}

func (gb GroupBench) ScalarAdd(iters int) {
	for i := 1; i < iters; i++ {
		gb.x.Add(gb.x, gb.y)
	}
}

func (gb GroupBench) ScalarSub(iters int) {
	for i := 1; i < iters; i++ {
		gb.x.Sub(gb.x, gb.y)
	}
}

func (gb GroupBench) ScalarNeg(iters int) {
	for i := 1; i < iters; i++ {
		gb.x.Neg(gb.x)
	}
}

func (gb GroupBench) ScalarMul(iters int) {
	for i := 1; i < iters; i++ {
		gb.x.Mul(gb.x, gb.y)
	}
}

func (gb GroupBench) ScalarDiv(iters int) {
	for i := 1; i < iters; i++ {
		gb.x.Div(gb.x, gb.y)
	}
}

func (gb GroupBench) ScalarInv(iters int) {
	for i := 1; i < iters; i++ {
		gb.x.Inv(gb.x)
	}
}

func (gb GroupBench) ScalarPick(iters int) {
	for i := 1; i < iters; i++ {
		gb.x.Fresh()
	}
}

func (gb GroupBench) ScalarEncode(iters int) {
	for i := 1; i < iters; i++ {
		gb.x.MarshalBinary()
	}
}

func (gb GroupBench) ScalarDecode(iters int) {
	for i := 1; i < iters; i++ {
		gb.x.UnmarshalBinary(gb.xe)
	}
}

func (gb GroupBench) PointAdd(iters int) {
	for i := 1; i < iters; i++ {
		gb.X.Add(gb.X, gb.Y)
	}
}

func (gb GroupBench) PointSub(iters int) {
	for i := 1; i < iters; i++ {
		gb.X.Sub(gb.X, gb.Y)
	}
}

func (gb GroupBench) PointNeg(iters int) {
	for i := 1; i < iters; i++ {
		gb.X.Neg(gb.X)
	}
}

func (gb GroupBench) PointMul(iters int) {
	for i := 1; i < iters; i++ {
		gb.X.Mul(gb.X, gb.y)
	}
}

func (gb GroupBench) PointBaseMul(iters int) {
	for i := 1; i < iters; i++ {
		gb.X.BaseMul(gb.y)
	}
}

func (gb GroupBench) PointPick(iters int) {
	for i := 1; i < iters; i++ {
		gb.X.Fresh()
	}
}

func (gb GroupBench) PointEncode(iters int) {
	for i := 1; i < iters; i++ {
		gb.X.MarshalBinary()
	}
}

func (gb GroupBench) PointDecode(iters int) {
	for i := 1; i < iters; i++ {
		gb.X.UnmarshalBinary(gb.Xe)
	}
}
