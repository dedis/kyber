//go:build !constantTime

package compatible_mod

import (
	"math/big"
)

type Mod = big.Int

func NewInt(x int64) *Mod {
	return big.NewInt(x)
}

// func Add(x, y *Int, _ int) *Int { return big.Add(x, y) }
