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
