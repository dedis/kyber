package bench

import (
	"testing"
	"dissent/crypto"
)


// A generic benchmark suite for abstract groups.
type GroupBench struct {
	b *testing.B
	g crypto.Group

	// Random secrets and points for testing
	x,y crypto.Secret
	X,Y crypto.Point
	xe []byte	// encoded Secret
	Xe []byte	// encoded Point
}

func newGroupBench(b *testing.B, g crypto.Group, len int) *GroupBench {
	var gb GroupBench
	gb.b = b
	gb.g = g
	gb.x = g.Secret().Pick(crypto.RandomStream)
	gb.y = g.Secret().Pick(crypto.RandomStream)
	gb.xe = gb.x.Encode()
	gb.X,_ = g.Point().Pick(nil, crypto.RandomStream)
	gb.Y,_ = g.Point().Pick(nil, crypto.RandomStream)
	gb.Xe = gb.X.Encode()
	b.SetBytes(int64(len))
	return &gb
}

func NewSecretBench(b *testing.B, g crypto.Group) *GroupBench {
	return newGroupBench(b, g, g.SecretLen())
}

func (gb GroupBench) SecretAdd() {
	for i := 1; i < gb.b.N; i++ {
		gb.x.Add(gb.x,gb.y)
	}
}

func (gb GroupBench) SecretSub() {
	for i := 1; i < gb.b.N; i++ {
		gb.x.Sub(gb.x,gb.y)
	}
}

func (gb GroupBench) SecretNeg() {
	for i := 1; i < gb.b.N; i++ {
		gb.x.Neg(gb.x)
	}
}

func (gb GroupBench) SecretMul() {
	for i := 1; i < gb.b.N; i++ {
		gb.x.Mul(gb.x,gb.y)
	}
}

func (gb GroupBench) SecretDiv() {
	for i := 1; i < gb.b.N; i++ {
		gb.x.Div(gb.x,gb.y)
	}
}

func (gb GroupBench) SecretInv() {
	for i := 1; i < gb.b.N; i++ {
		gb.x.Inv(gb.x)
	}
}

func (gb GroupBench) SecretPick() {
	for i := 1; i < gb.b.N; i++ {
		gb.x.Pick(crypto.RandomStream)
	}
}

func (gb GroupBench) SecretEncode() {
	for i := 1; i < gb.b.N; i++ {
		gb.x.Encode()
	}
}

func (gb GroupBench) SecretDecode() {
	for i := 1; i < gb.b.N; i++ {
		gb.x.Decode(gb.xe)
	}
}


func NewPointBench(b *testing.B, g crypto.Group) *GroupBench {
	return newGroupBench(b, g, g.PointLen())
}

func (gb GroupBench) PointAdd() {
	for i := 1; i < gb.b.N; i++ {
		gb.X.Add(gb.X,gb.Y)
	}
}

func (gb GroupBench) PointSub() {
	for i := 1; i < gb.b.N; i++ {
		gb.X.Sub(gb.X,gb.Y)
	}
}

func (gb GroupBench) PointNeg() {
	for i := 1; i < gb.b.N; i++ {
		gb.X.Neg(gb.X)
	}
}

func (gb GroupBench) PointMul() {
	for i := 1; i < gb.b.N; i++ {
		gb.X.Mul(gb.X,gb.y)
	}
}

func (gb GroupBench) PointBaseMul() {
	for i := 1; i < gb.b.N; i++ {
		gb.X.Mul(nil,gb.y)
	}
}

func (gb GroupBench) PointPick() {
	for i := 1; i < gb.b.N; i++ {
		gb.X.Pick(nil, crypto.RandomStream)
	}
}

func (gb GroupBench) PointEncode() {
	for i := 1; i < gb.b.N; i++ {
		gb.X.Encode()
	}
}

func (gb GroupBench) PointDecode() {
	for i := 1; i < gb.b.N; i++ {
		gb.X.Decode(gb.Xe)
	}
}

