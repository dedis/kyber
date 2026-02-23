//go:build !constantTime

package compatiblemod

import (
	"errors"
	"math/big"
)

type Mod struct {
	big.Int
}

func NewInt(x int64) *Mod {
	return &Mod{*big.NewInt(x)}
}

func NewUint(x uint64) *Mod {
	return &Mod{*big.NewInt(0).SetUint64(x)}
}

func (z *Mod) SetString(s string, base int) (*Mod, bool) {
	_, t := z.Int.SetString(s, base)
	return z, t
}

// NewModulusProduct creates a new modulus as the result of
// the multiplication of the two input byte arrays
func NewModulusProduct(a, b []byte) *Mod {
	aInt := new(big.Int).SetBytes(a)
	bInt := new(big.Int).SetBytes(b)
	mod := big.NewInt(0).Mul(aInt, bInt)
	return &Mod{*mod}
}

func FromString(s string, base int) (*Mod, error) {
	bigFromS, ok := new(big.Int).SetString(s, base)
	if !ok {
		return nil, errors.New("invalid string, cannot convert to a Modulus")
	}
	return &Mod{*bigFromS}, nil
}

func (z *Mod) SetBytes(buf []byte) *Mod {
	z.Int.SetBytes(buf)
	return z
}

func (z *Mod) ToBigInt() *big.Int {
	return &z.Int
}

func FromBigInt(x *big.Int) *Mod {
	return &Mod{*x}
}
