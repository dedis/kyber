//go:build !constantTime

package compatible

import (
	"crypto/rand"
	"errors"
	"io"
	"math/big"

	"go.dedis.ch/kyber/v4/compatible/compatiblemod"
)

type Int struct {
	big.Int
}

func NewInt(x int64) *Int {
	return &Int{*big.NewInt(x)}
}

func NewUint(x uint64) *Int {
	return &Int{*new(big.Int).SetUint64(x)}
}

func Jacobi(x, y *Int) int { return big.Jacobi(&x.Int, &y.Int) }

func Prime(randR io.Reader, bits int) (*Int, error) {
	random, err := rand.Prime(randR, bits)
	if err != nil {
		return nil, err
	}
	return &Int{*random}, err
}

func (z *Int) ToCompatibleMod() *compatiblemod.Mod {
	return &compatiblemod.Mod{Int: z.Int}
}

func FromCompatibleMod(mod *compatiblemod.Mod) *Int {
	return &Int{Int: mod.Int}
}

func FromBigInt(z *big.Int, _ *compatiblemod.Mod) *Int {
	return &Int{*z}
}
func (z *Int) ToBigInt() *big.Int {
	return &z.Int
}

func (z *Int) SetString(s, _ string, base int) (*Int, bool) {
	_, err := z.Int.SetString(s, base)
	return z, err
}

func (z *Int) SetStringM(s string, _ *compatiblemod.Mod, base int) (*Int, bool) {
	return z.SetString(s, s, base)
}

func (z *Int) Mul(a, b *Int, mod *compatiblemod.Mod) *Int {
	z.Int.Mul(&a.Int, &b.Int)
	z.Int.Mod(&z.Int, &mod.Int)
	return z
}

func (z *Int) Sub(a, b *Int, mod *compatiblemod.Mod) *Int {
	z.Int.Sub(&a.Int, &b.Int)
	z.Int.Mod(&z.Int, &mod.Int)
	return z
}

func (z *Int) Add(a, b *Int, mod *compatiblemod.Mod) *Int {
	z.Int.Add(&a.Int, &b.Int)
	z.Int.Mod(&z.Int, &mod.Int)
	return z
}

func (z *Int) SetUint64(x uint64) *Int {
	z.Int.SetUint64(x)
	return z
}

// Mod computes x mod y, sets the receiver to this result and return
// the receiver
func (z *Int) Mod(x *Int, y *compatiblemod.Mod) *Int {
	z.Int.Mod(&x.Int, &y.Int)
	return z
}

// SetBytesMod sets the byte of this Int and then mods the result to the
// given modulus. Ensures that the resulting Int is less than the given
// modulus.
func (z *Int) SetBytesMod(buf []byte, mod *compatiblemod.Mod) *Int {
	z.SetBytes(buf)
	z.Int.Mod(&z.Int, &mod.Int)
	return z
}

func (z *Int) SetBytesWithCheck(buf []byte, mod *compatiblemod.Mod) (*Int, error) {
	z.SetBytes(buf)
	if mod.Cmp(&z.Int) <= 0 {
		return z, errors.New("setting bytes overflows the modulus")
	}
	return z, nil
}

func (z *Int) Cmp(y *Int) (r int) {
	return z.Int.Cmp(&y.Int)
}

func (z *Int) Exp(x, y *Int, m *compatiblemod.Mod) *Int {
	z.Int.Exp(&x.Int, &y.Int, &m.Int)
	return z
}
func (z *Int) ModInverse(g *Int, n *compatiblemod.Mod) *Int {
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

func (z *Int) Bytes(_ *compatiblemod.Mod) []byte {
	return z.Int.Bytes()
}

// CmpGeqMod returns true if z >= mod otherwise 0
func (z *Int) CmpGeqMod(mod *compatiblemod.Mod) bool {
	return z.Int.Cmp(&mod.Int) >= 0
}
