//go:build constantTime

package compatible

import (
	rand2 "crypto/rand"
	"io"
	"math/big"

	"go.dedis.ch/kyber/v4/compatible/bigmod"
	"go.dedis.ch/kyber/v4/compatible/compatiblemod"
)

type Int struct {
	Int bigmod.Nat
}

func FromNat(x *bigmod.Nat) *Int {
	return &Int{*x}
}

func FromCompatibleMod(mod *compatiblemod.Mod) *Int {
	return &Int{Int: *mod.Nat()}
}

func NewInt(x int64) *Int {
	if x < 0 {
		panic("negative number")
	}
	var z = bigmod.NewNat().SetUint(uint(x))
	return &Int{*z}
}

func NewUint(x uint64) *Int {
	if x < 0 {
		panic("negative number")
	}
	var z = bigmod.NewNat().SetUint(uint(x))
	return &Int{*z}
}

func (z *Int) Int64() int64 {
	return z.ToBigInt().Int64()
}

func (z *Int) Uint64() uint64 {
	return z.ToBigInt().Uint64()
}

// Vartime function. Only to be used if the size of s is public
// The function also requires to pass a string to set the modulus, which determines the announced length of the Nat
// SetString sets z to s modulo m (s must be bigger than m, the program panics otherwise)
func (z *Int) SetString(s, sm string, base int) (*Int, bool) {
	bigFromS, ok := new(big.Int).SetString(s, base)
	if !ok {
		panic("invalid string for the value")
	}
	m, _ := compatiblemod.FromString(sm, base)
	res := FromBigInt(bigFromS, m)
	z.Int = res.Int
	return z, true
}

// SetStringM sets z to s modulo m (s must be bigger than m, the program panics otherwise)
func (z *Int) SetStringM(s string, m *compatiblemod.Mod, base int) (*Int, bool) {
	bigFromS, ok := new(big.Int).SetString(s, base)
	if !ok {
		panic("invalid string for the value")
	}
	res := FromBigInt(bigFromS, m)
	z.Int = res.Int
	return z, true
}

func (z *Int) Bytes(m *compatiblemod.Mod) []byte {
	return z.Int.Bytes(&m.Modulus)
}

// ModInverse sets z to the multiplicative inverse of g in the ring ℤ/nℤ
// Requires n to be prime (uses Fermat: g^(n-2) mod n).
func (z *Int) ModInverse(g *Int, n *compatiblemod.Mod) *Int {
	//if n.ToBigInt().ProbablyPrime(10) == false {
	//	panic("n is not prime")
	//}
	p := FromNat(n.Nat())                 // p = modulus as *Int
	exp := NewInt(0).Sub(p, NewInt(2), n) // exp = p - 2

	// If g == 0 modulo n, no inverse
	if g.Cmp(NewInt(0)) == 0 {
		return nil
	}

	res := NewInt(1)
	base := NewInt(0).Set(g) // copy of g

	// iterate from most-significant bit down to zero
	for i := exp.BitLen() - 1; i >= 0; i-- {
		// square: res = res * res mod n
		res = NewInt(0).Mul(res, res, n)

		if exp.Bit(i) == 1 {
			// multiply by base: res = res * base mod n
			res = NewInt(0).Mul(res, base, n)
		}
	}

	return z.Set(res)
}

func (z *Int) ModInverseVartime(g *Int, n *compatiblemod.Mod) *Int {
	z.Int.InverseVarTime(&g.Int, &n.Modulus)
	return z
}

// todo, normally fine if it's vartime (from its Kyber's usages (call it BitVartime)
func (z *Int) Bit(i int) uint {
	return z.Int.Bit(i)
}

// copied from saferith.Nat
func (z *Int) FillBytes(buf []byte) []byte {
	for i := 0; i < len(buf); i++ {
		buf[i] = 0
	}

	i := len(buf)
	// LEAK: Number of limbs
	// OK: The number of limbs is public
	// LEAK: The addresses touched in the out array
	// OK: Every member of out is touched
Outer:
	for _, x := range z.Int.Bits() {
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

func (z *Int) Text(base int) string { return z.ToBigInt().Text(base) }

// one usage in rand.go, maybe can be replaced by big.Int directly
func (z *Int) BitLen() int {
	// to get the real length
	return z.Int.BitLenVarTime()
	// to get the announced value
	// return z.Int.BitLenAnnounced()
}

// vartime wrapper around crypto/rand
func Prime(rand io.Reader, bits int) (*Int, error) {
	bigRandom, err := rand2.Prime(rand, bits)
	if err != nil {
		return nil, err
	}
	m := big.NewInt(0)
	m.SetBit(m, bits+1, 1)
	mod := compatiblemod.FromBigInt(m)

	return FromBigInt(bigRandom, mod), nil
}
func (z *Int) String() string { return z.ToBigInt().String() }
func (z *Int) Exp(x, y *Int, m *compatiblemod.Mod) *Int {
	// Exp requires y to be reduced modulo m
	y.Mod(y, m)
	z.Int.Exp(&x.Int, y.Bytes(m), &m.Modulus)
	return z
}

func (z *Int) Equal(s2 *Int) bool {
	return z.Int.Equal(&s2.Int) == 1

}

func (z *Int) Set(a *Int) *Int {
	z.Int.Set(&a.Int)
	//z.Int.Assign(1, &a.Int)
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

func (z *Int) Add(a, b *Int, mod *compatiblemod.Mod) *Int {
	z.Set(a)
	z.Int.Add(&b.Int, &mod.Modulus)
	return z
}

func (z *Int) Sub(a, b *Int, mod *compatiblemod.Mod) *Int {
	z.Set(a)
	z.Int.Sub(&b.Int, &mod.Modulus)
	return z
}

// Mul sets the receiver to the result of a * b mod m and returns the receiver
func (z *Int) Mul(a, b *Int, mod *compatiblemod.Mod) *Int {
	z.Int = *bigmod.NewNat().Set(&a.Int).Mul(&b.Int, &mod.Modulus)
	return z
}

// SetBytesMod sets the byte of this Int and then mods the result to the
// given modulus. Ensures that the resulting Int is less than the given
// modulus.
func (z *Int) SetBytesMod(buf []byte, mod *compatiblemod.Mod) *Int {
	// To create the Nat that will be reduced, we need a modulus big enough for it
	// take max between the buffer and the mod byte size to avoid using
	// a mod smaller than the actual modulus
	bufferSize := max(len(buf), len(mod.Bytes()))
	bigBuffer := make([]byte, bufferSize+1) // +1 to ensure the modulus is larger than the buffer value
	bigBuffer[0] = 1
	bigBufferMod, _ := bigmod.NewModulus(bigBuffer)

	y, err := bigmod.NewNat().SetBytes(buf, bigBufferMod)
	if err != nil {
		panic(err)
	}

	yReduced := bigmod.NewNat().Mod(y, &mod.Modulus)

	z.Int.Set(yReduced)
	return z
}

// SetBytesWithCheck attempts to set the bytes of this int and returns an error if
// the byte value is larger or equal to the modulus.
// This method simply calls bigmod.Nat.SetBytes() and return an error
// is this method return an error
func (z *Int) SetBytesWithCheck(buf []byte, mod *compatiblemod.Mod) (*Int, error) {
	_, err := z.Int.SetBytes(buf, &mod.Modulus)
	return z, err
}

func (z *Int) SetBytesBigBuffer(b []byte, m *compatiblemod.Mod) *Int {
	nat, err := z.Int.SetBytesBigBuffer(b, &m.Modulus)
	if err != nil {
		panic(err)
	}
	return FromNat(nat)
}

// Mod computes x mod y, sets the receiver to this result and return
// the receiver
func (z *Int) Mod(x *Int, y *compatiblemod.Mod) *Int {
	// Create a new Int and assign to z since bigmod.Nat.Mod() will overwrite the receiver
	z.Int = *bigmod.NewNat().Mod(&x.Int, &y.Modulus)
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
}

func (z *Int) Abs(x *Int) *Int {
	return z.Set(x)
}

// FromBigInt creates an Int from the given big.Int
// this function is var-time
func FromBigInt(z *big.Int, m *compatiblemod.Mod) *Int {
	return new(Int).SetBytesMod(z.Bytes(), m)
}

// ToBigInt returns this Int as a big.Int.
// this function is var-time
func (z *Int) ToBigInt() *big.Int {
	if z.IsZero() {
		return big.NewInt(0)
	}
	if z.Equal(NewInt(1)) {
		return big.NewInt(1)
	}

	// Create a modulo bigger than this int to be able to call SetBytes with it
	intByteSize := z.BitLen()/8 + 1
	modBytes := make([]byte, intByteSize+1)
	modBytes[0] = 1
	mod := new(compatiblemod.Mod).SetBytes(modBytes)

	zBytes := z.Bytes(mod)
	return big.NewInt(0).SetBytes(zBytes)
}

// CmpGeqMod returns true if z >= mod otherwise 0
func (z *Int) CmpGeqMod(mod *compatiblemod.Mod) bool {
	return z.Int.CmpGeq(mod.Nat()) == 1
}
