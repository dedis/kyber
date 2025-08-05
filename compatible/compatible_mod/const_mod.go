//go:build constantTime

package compatible_mod

import (
	"go.dedis.ch/kyber/v4/compatible/bigmod"
)

type Mod struct {
	*bigmod.Modulus
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
	return m.Nat()
}

func (z *Mod) SetString(s string, base int) (*Mod, bool) { panic("implement me") }

func (z *Mod) SetUint64(v uint64) *Mod {
	panic("implement me")
}

func (z *Mod) SetBytes(b []byte) (*Mod, error) {
	modulus, err := bigmod.NewModulus(b)
	if err != nil {
		return nil, err
	}
	return &Mod{modulus}, nil
}
