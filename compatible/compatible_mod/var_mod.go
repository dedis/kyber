//go:build !constantTime

package compatible_mod

import (
	"fmt"
	"math/big"
)

type Mod struct {
	*big.Int
}

func NewInt(x int64) *Mod {
	return &Mod{big.NewInt(x)}
}

func (z *Mod) SetString(s string, base int) (*Mod, bool) {
	if z.Int == nil {
		z.Int = new(big.Int)
	}
	_, t := z.Int.SetString(s, base)
	fmt.Println("	debug: ", t)
	return z, t
}

func (z *Mod) SetBytes(buf []byte) *Mod {
	if z.Int == nil {
		z.Int = new(big.Int)
	}
	z.Int.SetBytes(buf)
	return z
}

// func Add(x, y *Int, _ int) *Int { return big.Add(x, y) }
