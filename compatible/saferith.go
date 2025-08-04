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
	z.SetUint(uint(u))
	if mask != 0 {
		panic("negative nat")
	}
	//// 4. Conditionally negate: if mask&1==1 (i.e. n<0), do Neg(1), else Neg(0).
	////    Neg takes a saferith.Choice (alias of uint) and is branchless internally.
	//z.IsMinusOne()
	//z.Neg(bigmod.Choice(mask & 1))

	return &Int{z}
}

// the number of bytes to print in the string representation before an underscore
const underscoreAfterNBytes = 4

func (z *Int) String() string {

}

func (z *Int) SetString(s string, base int) (*Int, bool) { panic("implement me") }

func (z *Int) SetBit(x *Int, i int, b uint) *Int { panic("implement me") }

func (z *Int) Div(x, y *Int) *Int {
	//TODO implement me
	panic("implement me")
}

func (z *Int) BitLen() int {
	panic("implement me")
}
func (x *Int) FillBytes(buf []byte) []byte { panic("implement me") }

func (z *Int) Bytes() []byte {
	panic("implement me")
}

func (z *Int) ModInverse(g, n *Int) *Int {
	panic("implement me")
}

// not to be used
func (z *Int) ProbablyPrime(n int) bool { panic("implement me") }

func (x *Int) Text(base int) string { panic("implement me") }

func (x *Int) Bit(i int) uint { panic("implement me") }

// not to be used
func Prime(rand io.Reader, bits int) (*Int, error) { panic("implement me") }

func (z *Int) Exp(x, y, m *Int) *Int {
	z.Abs().ExpI(x.Abs(), y.Int, saferith.ModulusFromNat(m.Abs()))
	return z
}

func (z *Int) Equal(s2 *Int) bool {
	return z.Int.Eq(s2.Int) == 1

}

func (z *Int) Set(a *Int) *Int {
	z.Int = a.Int
	return z
}

func (z *Int) Int64() int64 {
	isNeg := z.Int.IsNegative()
	abs := z.Int.Abs()
	return int64(abs.Uint64()) * int64(isNeg)
}

func (z *Int) clone() *Int {
	return &Int{z.Int.Clone()}
}

func (z *Int) SetInt64(v int64) *Int {
	z.Int = NewInt(v).Int
	return z
}

func (z *Int) zero() *Int {
	z.Int.SetUint64(0)
	return z
}

func (z *Int) Add(a, b *Int) *Int {
	innerA := a.Int
	innerB := b.Int
	z.Int.Add(innerA, innerB, IntSize)
	return z
}

func (z *Int) Sub(a, b *Int) *Int {
	innerA := a.Int
	innerB := b.Int.Clone().Neg(1)
	z.Int.Add(innerA, innerB, IntSize)
	return z
}

func (z *Int) Neg(a *Int) *Int {
	innerA := a.Int
	z.Int = innerA.Clone().Neg(1)
	return z
}

func (z *Int) one() *Int {
	z.Int.SetUint64(1)
	return z
}

func (z *Int) Mul(a, b *Int) *Int {
	innerA := a.Int
	innerB := b.Int
	z.Int.Mul(innerA, innerB, IntSize)
	return z
}

func (z *Int) SetBytes(buf []byte) *Int {
	z.Int.SetBytes(buf)
	return z
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

func (z *Int) Sign() int {
	isNeg := z.IsNegative()
	isZero := z.Int.Abs().EqZero()

	var one = 4
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
