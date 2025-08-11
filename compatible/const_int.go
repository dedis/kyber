//go:build constantTime

package compatible

import (
	"go.dedis.ch/kyber/v4/compatible/bigmod"
	"go.dedis.ch/kyber/v4/compatible/compatible_mod"
	"io"
	"math/big"
)

type Int struct {
	Int bigmod.Nat
}

func FromNat(x *bigmod.Nat) *Int {
	return &Int{*x}
}

func NewInt(x int64) *Int {
	if x < 0 {
		panic("negative number")
	}
	var z = bigmod.NewNat().SetUint(uint(x))
	return &Int{*z}
}

// todo, vartime function. Only to be used if s is public
func (z *Int) SetString(s string, base int) (*Int, bool) {
	bigFromS, ok := new(big.Int).SetString(s, base)
	if !ok {
		panic("invalid string")
	}
	z = FromBigInt(bigFromS, z.ToCompatibleMod())
	return z, true
}

func (z *Int) Bytes() []byte {
	panic("implement me")
}

// todo vartime function
func (z *Int) ModInverse(g *Int, n *compatible_mod.Mod) *Int {
	z.Int.InverseVarTime(&g.Int, &n.Modulus)
	return z
}

// no usages found, probably only used in vartime only code
func (z *Int) SetBit(x *Int, i int, b uint) *Int {
	panic("implement me")
}

// one usage in rand.go, maybe can be replaced by big.Int directly
func (z *Int) BitLen() int {
	// to get the real length
	return z.Int.BitLenVarTime()
	// to get the announced value
	// return z.Int.BitLenAnnounced()
}

// not to be used
func Prime(rand io.Reader, bits int) (*Int, error) { panic("implement me") }

func (z *Int) Exp(x, y *Int, m *compatible_mod.Mod) *Int {
	z.Int.Exp(&x.Int, y.Bytes(), &m.Modulus)
	return z
}

func (z *Int) Equal(s2 *Int) bool {
	return z.Int.Equal(&s2.Int) == 1

}

func (z *Int) Set(a *Int) *Int {
	z.Int.Set(&a.Int)
	return z
}

func (z *Int) SetUint(v uint) *Int {
	z.Int = *bigmod.NewNat().SetUint(v)
	return z
}
func (z *Int) SetUint64(v uint64) *Int {
	z.Int = *bigmod.NewNat().SetUint(uint(v))
	return z
}

func (z *Int) zero() *Int {
	z.Int.SetUint(0)
	return z
}

// this function should take a Modulus
func (z *Int) Add(a, b *Int, mod *compatible_mod.Mod) *Int {
	z.Int.Set(&a.Int)
	z.Int.Add(&b.Int, &mod.Modulus)
	return z
}

func (z *Int) Sub(a, b *Int, mod *compatible_mod.Mod) *Int {
	z.Int.Set(&a.Int)
	z.Int.Sub(&b.Int, &mod.Modulus)
	return z
}

//func (z *Int) Neg(a *Int) *Int {
//	innerA := a.Int
//	z.Int = innerA.Clone().Neg(1)
//	return z
//}

func (z *Int) one() *Int {
	z.Int.SetUint(1)
	return z
}

func (z *Int) Mul(a, b *Int, mod *compatible_mod.Mod) *Int {
	z.Int.Set(&a.Int)
	z.Int.Mul(&b.Int, &mod.Modulus)
	return z
}

func (z *Int) SetBytes(buf []byte, mod *compatible_mod.Mod) *Int {
	_, err := z.Int.SetBytes(buf, &mod.Modulus)
	if err != nil {
		panic(err)
	}
	return z
}

func (z *Int) Mod(x *Int, y *compatible_mod.Mod) *Int {
	z.Int.Mod(&x.Int, &y.Modulus)
	return z
}

func (z *Int) Sign() int {
	return 1 - int(z.Int.IsZero())
}

func (z *Int) IsZero() bool {
	return z.Int.IsZero() == 1
}

func (z *Int) Cmp(x *Int) int {

	greaterOrEqual := 2 * int(z.Int.CmpGeq(&x.Int))
	equal := int(z.Int.Equal(&x.Int))
	return greaterOrEqual - equal - 1
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
	//
	//nat := bigmod.NewNat()
	//nat.Assign(greaterOrEqual, bigmod.NewNat().SetUint(2))
	//nat.Assign(bigmod.Choice(equal), bigmod.NewNat().SetUint(1))
	//nat.Assign(bigmod.Not(greaterOrEqual), bigmod.NewNat().SetUint(0))
	//return nat.
}

func (z *Int) Abs(x *Int) *Int {
	return z.Set(x)
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

func (z *Int) ToCompatibleMod() *compatible_mod.Mod {
	mod, err := bigmod.NewModulusFromNat(&z.Int)
	if err != nil {
		panic(err)
	}
	return &compatible_mod.Mod{Modulus: *mod}
}

func FromBigInt(z *big.Int, m *compatible_mod.Mod) *Int {
	nat, err := bigmod.NewNat().SetBytes(z.Bytes(), &m.Modulus)
	if err != nil {
		panic(err)
	}
	return &Int{*nat}
}

func (z *Int) ToBigInt() *big.Int {
	return big.NewInt(0).SetBytes(z.Bytes())
}
