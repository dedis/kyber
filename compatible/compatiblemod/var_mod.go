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

func (z *Mod) SetString(s string, base int) (*Mod, bool) {
	_, t := z.Int.SetString(s, base)
	//fmt.Println("	debug: ", t)
	return z, t
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
