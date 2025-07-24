//go:build constantTime

package compatible

import (
	"github.com/cronokirby/saferith"
)

var IntSize = 64

type Int struct {
	*saferith.Int
}

func NewInt(x int64) Int {
	var z *saferith.Int = new(saferith.Int)

	// 1. Compute mask = 0 if n>=0, all-bits-1 if n<0.
	//    In Go, right-shifting a signed negative replicates the sign bit.
	mask := uint64(x >> 63)

	// 2. Compute absolute value without branching:
	//    u = (uint64(n) ^ mask) - mask
	//    If mask==0: u = uint64(n)
	//    If mask==0xFF…: u = ^uint64(n) + 1 = -uint64(n)
	u := (uint64(x) ^ mask) - mask

	// 3. Load the magnitude into z (branchless).
	z.SetUint64(u)

	// 4. Conditionally negate: if mask&1==1 (i.e. n<0), do Neg(1), else Neg(0).
	//    Neg takes a saferith.Choice (alias of uint) and is branchless internally.
	z.Neg(saferith.Choice(mask & 1))

	return Int{z}
}

func (i Int) String() string {
	return i.Int.String()
}

func (z *Int) SetBit(x *Int, i int, b uint) *Int { panic("implement me") }

func (i Int) Div(a, b Int) Int {
	//TODO implement me
	panic("implement me")
}

func (i Int) BitLen() int {
	panic("implement me")
}

func (i Int) Bytes() interface{} {
	panic("implement me")
}

func (i Int) ModInverse(c *Int, m *Int) Int {
	panic("implement me")
}

func (i Int) Int64() int64 {
	panic("implement me")
}

func (x *Int) ProbablyPrime(n int) bool { panic("implement me") }

func (i Int) Equal(s2 Int) bool {
	return i.Int.Eq(s2.Int) == 1

}

func (i Int) Set(a Int) Int {
	i.Int = a.Int
	return i
}

func (i Int) Clone() Int {
	return Int{i.Int.Clone()}
}

func (i Int) SetInt64(v int64) Int {
	z := NewInt(v)
	i.Int = z.Int
	return i
}

func (i Int) Zero() Int {
	i.Int.SetUint64(0)
	return i
}

func (i Int) Add(a, b Int) Int {
	innerA := a.Int
	innerB := b.Int
	i.Int.Add(innerA, innerB, IntSize)
	return i
}

func (i Int) Sub(a, b Int) Int {
	innerA := a.Int
	innerB := b.Int.Clone().Neg(1)
	i.Int.Add(innerA, innerB, IntSize)
	return i
}

func (i Int) Neg(a Int) Int {
	innerA := a.Int
	i.Int = innerA.Clone().Neg(1)
	return i
}

func (i Int) One() Int {
	i.Int.SetUint64(1)
	return i
}

func (i Int) Mul(a, b Int) Int {
	innerA := a.Int
	innerB := b.Int
	i.Int.Mul(innerA, innerB, IntSize)
	return i
}

func (i Int) SetBytes(bytes []byte) Int {
	i.Int.SetBytes(bytes)
	return i
}

func (z *Int) Mod(x, y *Int) *Int {
	if y.Int.IsNegative() == 1 {
		panic("negative modulus")
	}
	m := saferith.ModulusFromNat(y.Int.Abs())
	z.Int = x.Int.Clone()
	z.Int.Mod(m)
	return z
}

func (i Int) Sign() int {
	isNeg := i.IsNegative()
	isZero := i.Int.Abs().EqZero()

	var one int = 4
	if isNeg == 1 {
		one = -1
	} else {
		one = 1
	}
	if isZero == 1 {
		one = 0
	} else {
		one = one
	}
	return one
}

func (z *Int) Cmp(x *Int) int {
	if z.IsNegative() == 1 || x.IsNegative() == 1 {
		panic("Cmp between negative numbers is not implemented")
	}

	bigger, _, less := z.Int.Abs().Cmp(x.Int.Abs())
	//res := 10
	//if bigger == 1 {
	//	res = 1
	//}
	//if equal == 1 {
	//	res = 0
	//}
	//if smaller == 1 {
	//	res = -1
	//}
	//return res

	nat := new(saferith.Nat).SetUint64(1)
	nat.CondAssign(bigger, new(saferith.Nat).SetUint64(2))
	nat.CondAssign(less, new(saferith.Nat).SetUint64(0))
	return int(nat.Uint64()) - 1
}

//Bytes, SetString, Cmp

//	func (i *Int) Equal(x Int) bool {
//		x
//		return i.Eq(x) == 1
//	}
//
//	func (i *Int) Set(a Int) Int {
//		i.Set(&a)
//		return *i
//	}
