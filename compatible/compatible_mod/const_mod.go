//go:build constantTime

package compatible_mod

import (
	"math/big"

	"go.dedis.ch/kyber/v4/compatible/bigmod"
)

type Mod struct {
	bigmod.Modulus
}

func (m *Mod) Nat() *bigmod.Nat {
	return m.Modulus.Nat()
}

// vartime function
func (m *Mod) SetString(s string, base int) (*Mod, bool) {
	bigFromS, ok := new(big.Int).SetString(s, base)
	if !ok {
		panic("invalid string, cannot convert to a Modulus")
	}
	m = FromBigInt(bigFromS)
	return m, true
}

func FromString(s string, base int) (*Mod, bool) {
	bigFromS, ok := new(big.Int).SetString(s, base)
	if !ok {
		panic("invalid string, cannot convert to a Modulus")
	}
	z := FromBigInt(bigFromS)
	return z, true
}

func (m *Mod) SetBytes(b []byte) *Mod {
	modulus, err := bigmod.NewModulus(b)
	if err != nil {
		panic(err)
	}
	return &Mod{*modulus}
}

// one usage in group/edwards22519/point_test.go @ TestPointIsCanonical
func (m *Mod) Bytes() []byte {
	return m.Modulus.Nat().Bytes(&m.Modulus)
}

func NewInt(x int64) *Mod {
	if x < 1 {
		panic("negative number")
	}
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

func (m *Mod) ToBigInt() *big.Int {
	return big.NewInt(0).SetBytes(m.Bytes())
}

func (m *Mod) SetBigInt(big *big.Int) *Mod {
	return m.SetBytes(big.Bytes())
}

func (m *Mod) Bit(i int) uint {
	return m.Modulus.Nat().Bit(i)
}

func (m *Mod) String() string { return m.ToBigInt().String() }
