//go:build !constantTime

package compatible_mod

import (
	"math/big"
)

type Mod struct {
	*big.Int
}

func NewInt(x int64) *Mod {
	return &Mod{big.NewInt(x)}
}

func (m *Mod) SetBytes(b []byte) (*Mod, error) {
	return &Mod{big.NewInt(0).SetBytes(b)}, nil
}

// func Add(x, y *Int, _ int) *Int { return big.Add(x, y) }
