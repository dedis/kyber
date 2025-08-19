//go:build constantTime

package compatible_mod

import (
	"go.dedis.ch/kyber/v4/compatible/bigmod"
	"math/big"
)

type Mod struct {
	bigmod.Modulus
}

//func NewInt(x int64) *Mod {
//	if x <= 1 {
//		panic("negative number")
//	}
//	mod, err := bigmod.NewModulusFromNat(bigmod.NewNat().SetUint(uint(x)))
//	if err != nil {
//		panic(err)
//	}
//	return mod
//
//}

func (m *Mod) Nat() *bigmod.Nat {
	return m.Modulus.Nat()
}

// vartime function
func (z *Mod) SetString(s string, base int) (*Mod, bool) {
	bigFromS, ok := new(big.Int).SetString(s, base)
	if !ok {
		panic("invalid string, cannot convert to a Modulus")
	}
	z = FromBigInt(bigFromS)
	return z, true
}

func FromString(s string, base int) (*Mod, bool) {
	bigFromS, ok := new(big.Int).SetString(s, base)
	if !ok {
		panic("invalid string, cannot convert to a Modulus")
	}
	z := FromBigInt(bigFromS)
	return z, true
}

func (z *Mod) SetBytes(b []byte) *Mod {
	modulus, err := bigmod.NewModulus(b)
	if err != nil {
		panic(err)
	}
	return &Mod{*modulus}
}

// one usage in group/edwards22519/point_test.go @ TestPointIsCanonical
func (z *Mod) Bytes() []byte {
	return z.Modulus.Nat().Bytes(&z.Modulus)
}

func NewInt(x int64) *Mod {
	mod, err := bigmod.NewModulusFromNat(bigmod.NewNat().SetUint(uint(x)))
	if err != nil {
		panic(err)
	}
	return &Mod{*mod}
}

func FromBigInt(x *big.Int) *Mod {
	modulus, err := bigmod.NewModulus(x.Bytes())
	if err != nil {
		panic(err)
	}
	return &Mod{*modulus}
}

func (z *Mod) SetBigInt(big *big.Int) *Mod {
	return z.SetBytes(big.Bytes())
}

func (z *Mod) Bit(i int) uint {
	return z.Modulus.Nat().Bit(i)
}
