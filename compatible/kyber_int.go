//go:build !constantTime

package compatible

import (
	"crypto/rand"
	"io"
	"math/big"
)

type Int = big.Int

func NewInt(x int64) *Int {
	return big.NewInt(x)
}

func Jacobi(x, y *Int) int { return big.Jacobi(x, y) }

func Prime(randR io.Reader, bits int) (*Int, error) {
	return rand.Prime(randR, bits)
}

// func Add(x, y *Int, _ int) *Int { return big.Add(x, y) }
