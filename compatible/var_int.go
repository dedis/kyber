//go:build !constantTime

package compatible

import (
	"crypto/rand"
	"go.dedis.ch/kyber/v4/compatible/compatible_mod"
	"io"
	"math/big"
)

type Int struct {
	big.Int
}

func NewInt(x int64) *Int {
	return &Int{*big.NewInt(x)}
}

func Jacobi(x, y *Int) int { return big.Jacobi(&x.Int, &y.Int) }

func Prime(randR io.Reader, bits int) (*Int, error) {
	random, err := rand.Prime(randR, bits)
	if err != nil {
		return nil, err
	}
	return &Int{*random}, err
}

func (z *Int) ToCompatibleMod() *compatible_mod.Mod {
	return &compatible_mod.Mod{Int: z.Int}
}

func FromCompatibleMod(mod *compatible_mod.Mod) *Int {
	return &Int{Int: mod.Int}
}

func FromBigInt(z *big.Int, _ *compatible_mod.Mod) *Int {
	return &Int{*z}
}
func (z *Int) ToBigInt() *big.Int {
	return &z.Int
}

func (z *Int) SetString(s, _ string, base int) (*Int, bool) {
	_, err := z.Int.SetString(s, base)
	return z, err
}

func (z *Int) Mul(a, b *Int, mod *compatible_mod.Mod) *Int {
	z.Int.Mul(&a.Int, &b.Int)
	z.Int.Mod(&z.Int, &mod.Int)
	return z
}

func (z *Int) Sub(a, b *Int, mod *compatible_mod.Mod) *Int {
	z.Int.Sub(&a.Int, &b.Int)
	z.Int.Mod(&z.Int, &mod.Int)
	return z
}

func (z *Int) Add(a, b *Int, mod *compatible_mod.Mod) *Int {
	z.Int.Add(&a.Int, &b.Int)
	z.Int.Mod(&z.Int, &mod.Int)
	return z
}

func (z *Int) SetUint64(x uint64) *Int {
	z.Int.SetUint64(x)
	return z
}

func (z *Int) Mod(x *Int, y *compatible_mod.Mod) *Int {
	z.Int.Mod(&x.Int, &y.Int)
	return z
}

func (z *Int) SetBytes(buf []byte, mod *compatible_mod.Mod) *Int {
	z.Int.SetBytes(buf)
	z.Int.Mod(&z.Int, &mod.Int)
	return z
}

func (x *Int) Cmp(y *Int) (r int) {
	return x.Int.Cmp(&y.Int)
}

func (z *Int) Exp(x, y *Int, m *compatible_mod.Mod) *Int {
	z.Int.Exp(&x.Int, &y.Int, &m.Int)
	return z
}
func (z *Int) ModInverse(g *Int, n *compatible_mod.Mod) *Int {
	z.Int.ModInverse(&g.Int, &n.Int)
	return z
}

func (z *Int) SetInt64(x int64) *Int {
	z.Int.SetInt64(x)
	return z
}

func (z *Int) Set(x *Int) *Int {
	z.Int.Set(&x.Int)
	return z
}

func (z *Int) SetBit(x *Int, i int, b uint) *Int {
	z.Int.SetBit(&x.Int, i, b)
	return z
}

func (z *Int) Bytes(_ *compatible_mod.Mod) []byte {
	return z.Int.Bytes()
}
