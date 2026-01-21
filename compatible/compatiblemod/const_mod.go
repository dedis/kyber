//go:build constantTime

package compatiblemod

import (
	"encoding/binary"
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
	xBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(xBytes, uint64(x))
	mod, err := bigmod.NewModulus(xBytes)
	if err != nil {
		panic(err)
	}
	return &Mod{*mod}
}

func NewUint(x uint64) *Mod {
	if x < 1 {
		panic("Modulus needs to be larger than 1")
	}
	xBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(xBytes, uint64(x))
	mod, err := bigmod.NewModulus(xBytes)
	if err != nil {
		panic(err)
	}
	return &Mod{*mod}
}

// NewModulusProduct creates a new modulus as the result of
// the multiplication of the two input byte arrays
func NewModulusProduct(a, b []byte) *Mod {
	mod, err := bigmod.NewModulusProduct(a, b)
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
