//go:build constantTime

package compatible

import (
	rand2 "crypto/rand"
	"go.dedis.ch/kyber/v4/compatible/bigmod"
	"go.dedis.ch/kyber/v4/compatible/compatible_mod"
	"io"
	"math/big"
)

type Int struct {
	Int bigmod.Nat
}

func FromNat(x *bigmod.Nat) *Int {
	return &Int{*x}
}

func NewInt(x int64) *Int {
	if x < 0 {
		panic("negative number")
	}
	var z = bigmod.NewNat().SetUint(uint(x))
	return &Int{*z}
}

// Vartime function. Only to be used if the size of s is public
// The function also requires to pass a string to set the modulus, which determines the announced length of the Nat
// SetString sets z to s modulo m (s must be bigger than m, the program panics otherwise)
func (z *Int) SetString(s, sm string, base int) (*Int, bool) {
	bigFromS, ok := new(big.Int).SetString(s, base)
	if !ok {
		panic("invalid string for the value")
	}
	m, _ := compatible_mod.FromString(sm, base)
	z = FromBigInt(bigFromS, m)
	return z, true
}

// SetStringM sets z to s modulo m (s must be bigger than m, the program panics otherwise)
func (z *Int) SetStringM(s string, m *compatible_mod.Mod, base int) (*Int, bool) {
	bigFromS, ok := new(big.Int).SetString(s, base)
	if !ok {
		panic("invalid string for the value")
	}
	z = FromBigInt(bigFromS, m)
	return z, true
}

func (z *Int) Bytes(m *compatible_mod.Mod) []byte {
	return z.Int.Bytes(&m.Modulus)
}

// leaks the size of z
func (z *Int) bytesVartime() []byte {
	return z.Int.Bytes(&z.ToCompatibleMod().Modulus)
}

// ModInverse sets z to the multiplicative inverse of g in the ring ℤ/nℤ
func (z *Int) ModInverse(g *Int, n *compatible_mod.Mod) *Int {
	res := NewInt(1)

	// Modular inversion in a multiplicative group is a^(phi(m)-1) = a^-1 mod m
	// Since m is prime, phi(m) = m - 1 => a^(m-2) = a^-1 mod m.
	// The inverse is computed using the exponentation-and-square algorithm.
	// Implementation is constant time regarding the value a, it only depends on
	// the modulo.
	for i := 255; i >= 0; i-- {
		bit := n.Bit(i)
		// square step
		res.Mul(res, res, n)
		if bit == 1 {
			// multiply step
			res.Mul(res, g, n)
		}
	}
	z = res
	return z
}

func (z *Int) ModInverseVartime(g *Int, n *compatible_mod.Mod) *Int {
	z.Int.InverseVarTime(&g.Int, &n.Modulus)
	return z
}

// todo, normally fine if it's vartime (from its Kyber's usages (call it BitVartime)
func (x *Int) Bit(i int) uint {
	return x.Int.Bit(i)
}

// copied from saferith.Nat
func (x *Int) FillBytes(buf []byte) []byte {
	for i := 0; i < len(buf); i++ {
		buf[i] = 0
	}

	i := len(buf)
	// LEAK: Number of limbs
	// OK: The number of limbs is public
	// LEAK: The addresses touched in the out array
	// OK: Every member of out is touched
Outer:
	for _, x := range x.Int.Bits() {
		y := x
		for j := 0; j < bigmod.LimbsSizeInBytes(); j++ {
			i--
			if i < 0 {
				break Outer
			}
			buf[i] = byte(y)
			y >>= 8
		}
	}
	return buf
}

func (x *Int) Text(base int) string { panic("implement me") }

// one usage in rand.go, maybe can be replaced by big.Int directly
func (z *Int) BitLen() int {
	// to get the real length
	return z.Int.BitLenVarTime()
	// to get the announced value
	// return z.Int.BitLenAnnounced()
}

// vartime wrapper around crypto/rand
func Prime(rand io.Reader, bits int) (*Int, error) {
	big, err := rand2.Prime(rand, bits)
	if err != nil {
		return nil, err
	}
	m := big.SetUint64(0)
	mod := compatible_mod.FromBigInt(m.SetBit(big.SetUint64(0), bits, 1))

	return FromBigInt(big, mod), nil
}
func (z *Int) String() string { panic("implement me") }
func (z *Int) Exp(x, y *Int, m *compatible_mod.Mod) *Int {
	// Exp requires y to be reduced modulo m
	y.Int.Mod(&y.Int, &m.Modulus)
	z.Int.Exp(&x.Int, y.Bytes(m), &m.Modulus)
	return z
}

func (z *Int) Equal(s2 *Int) bool {
	return z.Int.Equal(&s2.Int) == 1

}

func (z *Int) Set(a *Int) *Int {
	z.Int.Set(&a.Int)
	return z
}

func (z *Int) SetUint(v uint) *Int {
	z.Int = *bigmod.NewNat().SetUint(v)
	return z
}
func (z *Int) SetUint64(v uint64) *Int {
	z.Int = *bigmod.NewNat().SetUint(uint(v))
	return z
}

func (z *Int) zero() *Int {
	z.Int.SetUint(0)
	return z
}

func (z *Int) Add(a, b *Int, mod *compatible_mod.Mod) *Int {
	z.Int.Set(&a.Int)
	z.Int.Add(&b.Int, &mod.Modulus)
	return z
}

func (z *Int) Sub(a, b *Int, mod *compatible_mod.Mod) *Int {
	z.Int.Set(&a.Int)
	z.Int.Sub(&b.Int, &mod.Modulus)
	return z
}

//func (z *Int) Neg(a *Int) *Int {
//	innerA := a.Int
//	z.Int = innerA.Clone().Neg(1)
//	return z
//}

func (z *Int) one() *Int {
	z.Int.SetUint(1)
	return z
}

func (z *Int) Mul(a, b *Int, mod *compatible_mod.Mod) *Int {
	z.Int.Set(&a.Int)
	z.Int.Mul(&b.Int, &mod.Modulus)
	return z
}

func (z *Int) SetBytes(buf []byte, mod *compatible_mod.Mod) *Int {
	_, err := z.Int.SetBytes(buf, &mod.Modulus)
	if err != nil {
		panic(err)
	}
	return z
}

func (z *Int) Mod(x *Int, y *compatible_mod.Mod) *Int {
	z.Int.Mod(&x.Int, &y.Modulus)
	return z
}

func (z *Int) Sign() int {
	return 1 - int(z.Int.IsZero())
}

func (z *Int) IsZero() bool {
	return z.Int.IsZero() == 1
}

func (z *Int) Cmp(x *Int) int {

	greaterOrEqual := 2 * int(z.Int.CmpGeq(&x.Int))
	equal := int(z.Int.Equal(&x.Int))
	return greaterOrEqual - equal - 1
	//res := 10
	//if bigger == 1 {
	//	res = 1
	//}
	//if equal == 1 {
	//	res = 0
	//}
	//if smaller == 1 {
	//	res = -1
	//}
	//return res
	//
	//nat := bigmod.NewNat()
	//nat.Assign(greaterOrEqual, bigmod.NewNat().SetUint(2))
	//nat.Assign(bigmod.Choice(equal), bigmod.NewNat().SetUint(1))
	//nat.Assign(bigmod.Not(greaterOrEqual), bigmod.NewNat().SetUint(0))
	//return nat.
}

func (z *Int) Abs(x *Int) *Int {
	return z.Set(x)
}

func (z *Int) ToCompatibleMod() *compatible_mod.Mod {
	mod, err := bigmod.NewModulusFromNat(&z.Int)
	if err != nil {
		panic(err)
	}
	return &compatible_mod.Mod{Modulus: *mod}
}

// todo this function is vartime
func FromBigInt(z *big.Int, m *compatible_mod.Mod) *Int {
	nat, err := bigmod.NewNat().SetBytes(z.Bytes(), &m.Modulus)
	if err != nil {
		panic(err)
	}
	return &Int{*nat}
}

// todo this function is vartime
func (z *Int) ToBigInt() *big.Int {
	return big.NewInt(0).SetBytes(z.bytesVartime())
}
