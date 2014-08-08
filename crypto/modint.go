package crypto

import (
	"errors"
	"math/big"
	//"encoding/hex"
	"crypto/cipher"
)


var one = big.NewInt(1)
var two = big.NewInt(2)


// ModInt is a generic implementation of finite field arithmetic
// on integer finite fields with a given constant modulus,
// built using Go's built-in big.Int package.
// ModInt satisfies the abstract Secret interface,
// and hence serves as a basic implementation of Secret,
// e.g., representing discrete-log exponents of Schnorr groups
// or scalar multipliers for elliptic curves.
//
// ModInt offers an API similar to and compatible with big.Int,
// but a ModInt "carries around" a pointer to the relevant modulus
// and automatically normalizes the value to that modulus
// after all arithmetic operations, simplifying modular arithmetic.
// All operations assume that the source(s) and destination objects
// have the same modulus, but do not check this assumption.
// Arithmetic operations always use the modulus in the target object
// to normalize the results of the operation.
//
// For efficiency the modulus field M is a pointer,
// whose target is assumed never to change.
// To ensure that the modulus pointer is properly initialized,
// either allocate new instances with NewModInt()
// or initialize them explicitly with Init() or Set().
//
type ModInt struct {
	V big.Int 		// Integer value from 0 through M-1
	M *big.Int		// Modulus for finite field arithmetic
}

// Create a new ModInt with a given int64 value and big.Int modulus.
func NewModInt(v int64, M *big.Int) *ModInt {
	return new(ModInt).Init(v,M)
}

// Initialize a ModInt with an int64 value and big.Int modulus.
func (i *ModInt) Init(v int64, M *big.Int) *ModInt {
	if v != 0 {
		i.V.SetInt64(v)
	}
	i.M = M
	return i
}

// Return the ModInt's integer value in decimal string representation.
func (i *ModInt) String() string { return i.V.String() }

// Compare two ModInts for equality or inequality
func (i *ModInt) Cmp(s2 Secret) int {
	return i.V.Cmp(&s2.(*ModInt).V)
}

// Test two ModInts for equality
func (i *ModInt) Equal(s2 Secret) bool {
	return i.V.Cmp(&s2.(*ModInt).V) == 0
}

// Returns true if the integer value is nonzero.
func (i *ModInt) Nonzero(s2 Secret) bool {
	return i.V.Sign() != 0
}

// Set both value and modulus to be equal to another ModInt.
// Since this method copies the modulus as well,
// it may be used as an alternative to Init().
func (i *ModInt) Set(a Secret) Secret {
	i.V.Set(&a.(*ModInt).V)
	return i
}

// Set to the value 0.
func (i *ModInt) Zero() Secret {
	i.V.SetInt64(0)
	return i
}

// Set to the value 1.
func (i *ModInt) One() Secret {
	i.V.SetInt64(1)
	return i
}

// Set to an arbitrary 64-bit "small integer" value.
func (i *ModInt) SetInt64(v int64) Secret {
	i.V.SetInt64(v).Mod(&i.V, i.M)
	return i
}

// Return the int64 representation of the value.
// If the value is not representable in an int64 the result is undefined.
func (i *ModInt) Int64() int64 {
	return i.V.Int64()
}

// Set to an arbitrary uint64 value.
func (i *ModInt) SetUint64(v uint64) Secret {
	i.V.SetUint64(v).Mod(&i.V, i.M)
	return i
}

// Return the uint64 representation of the value.
// If the value is not representable in an uint64 the result is undefined.
func (i *ModInt) Uint64() uint64 {
	return i.V.Uint64()
}

// Set to a + b mod M.
func (i *ModInt) Add(a,b Secret) Secret {
	i.V.Add(&a.(*ModInt).V,&b.(*ModInt).V).Mod(&i.V, i.M)
	return i
}

// Set to a - b mod M.
func (i *ModInt) Sub(a,b Secret) Secret {
	i.V.Sub(&a.(*ModInt).V,&b.(*ModInt).V).Mod(&i.V, i.M)
	return i
}

// Set to -a mod M.
func (i *ModInt) Neg(a Secret) Secret {
	v := &a.(*ModInt).V
	if v.Sign() > 0 {
		i.V.Sub(i.M, v)
	} else {
		i.V.SetUint64(0)
	}
	return i
}

// Set to a * b mod M.
func (i *ModInt) Mul(a,b Secret) Secret {
	i.V.Mul(&a.(*ModInt).V,&b.(*ModInt).V).Mod(&i.V, i.M)
	return i
}

// Set to a * b^-1 mod M, where b^-1 is the modular inverse of b.
func (i *ModInt) Div(a,b Secret) Secret {
	var t big.Int
	i.V.Mul(&a.(*ModInt).V, t.ModInverse(&b.(*ModInt).V, i.M))
	i.V.Mod(&i.V, i.M)
	return i
}

// Set to the modular inverse of a with respect to modulus M.
func (i *ModInt) Inv(a Secret) Secret {
	i.V.ModInverse(&a.(*ModInt).V, i.M)
	return i
}

// Set to a^e mod M,
// where e is an arbitrary big.Int exponent (not necessarily 0 <= e < M).
func (i *ModInt) Exp(a Secret, e *big.Int) Secret {
	i.V.Exp(&a.(*ModInt).V, e, i.M)
	return i
}

// Compute the Legendre symbol of a, if modulus M is prime.
func (i *ModInt) legendre() int {
	var Pm1,v big.Int
	Pm1.Sub(i.M,one)
	v.Div(&Pm1,two)
	v.Exp(&i.V,&v,i.M)
	if v.Cmp(&Pm1) == 0 {
		return -1
	}
	return v.Sign()
}

// Compute sqrt(a) mod M of one exists.
// Assumes the modulus M is an odd prime.
// Returns true on success, false if input a is not a square.
// (This really should be part of Go's big.Int library.)
func (i *ModInt) Sqrt(as Secret) bool {
	p := i.M			// prime modulus

	ai := as.(*ModInt)
	a := &ai.V
	if a.Sign() == 0 {
		i.SetInt64(0)		// sqrt(0) = 0
		return true
	}
	if ai.legendre() != 1 {
		return false		// not a square mod M
	}

	// Break p-1 into s*2^e such that s is odd.
	var s big.Int
	var e int
	s.Sub(p,one)
	for s.Bit(0) == 0 {
		s.Div(&s,two)
		e++
	}

	// Find some non-square n
	var ni ModInt
	ni.Init(2,p)
	n := &ni.V
	for ni.legendre() != -1 {
		n.Add(n,one)
	}

	// Heart of the Tonelli-Shanks algorithm.
	// Follows the description in
	// "Square roots from 1; 24, 51, 10 to Dan Shanks" by Ezra Brown.
	var x,b,g,t big.Int
	x.Add(&s,one).Div(&x,two).Exp(a,&x,p)
	b.Exp(a,&s,p)
	g.Exp(n,&s,p)
	r := e
	for {
		// Find the least m such that ord_p(b) = 2^m
		var m int
		t.Set(&b)
		for t.Cmp(one) != 0 {
			t.Exp(&t,two,p)
			m++
		}

		if m == 0 {
			i.V.Set(&x)
			return true
		}

		t.SetInt64(0).SetBit(&t,r-m-1,1).Exp(&g,&t,p)
					// t = g^(2^(r-m-1)) mod p
		g.Mul(&t,&t).Mod(&g,p)	// g = g^(2^(r-m)) mod p
		x.Mul(&x,&t).Mod(&x,p)
		b.Mul(&b,&g).Mod(&b,p)
		r = m
	}
}

// Pick a [pseudo-]random integer modulo M
// using bits from the given stream cipher.
func (i *ModInt) Pick(rand cipher.Stream) Secret {
	i.V.Set(RandomBigInt(i.M,rand))
	return i
}

// Return the length in bytes of encoded integers with modulus M.
// The length of encoded ModInts depends only on the size of the modulus,
// and not on the the value of the encoded integer,
// making the encoding is fixed-length for simplicity and security.
func (i *ModInt) Len() int {
	return (i.M.BitLen()+7)/8
}

// Encode the value of this ModInt into a byte-slice exactly Len() bytes long.
func (i *ModInt) Encode() []byte {
	l := i.Len()
	b := i.V.Bytes()	// may be shorter than l
	if ofs := l-len(b); ofs != 0 {
		nb := make([]byte,l)
		copy(nb[ofs:],b)
		return nb
	}
	return b
}

// Attempt to decode a ModInt from a byte-slice buffer.
// Returns an error if the buffer is not exactly Len() bytes long
// or if the contents of the buffer represents an out-of-range integer.
func (i *ModInt) Decode(buf []byte) error {
	if len(buf) != i.Len() {
		return errors.New("ModInt.Decode: wrong size buffer")
	}
	i.V.SetBytes(buf)
	if i.V.Cmp(i.M) >= 0 {
		return errors.New("ModInt.Decode: value out of range")
	}
	return nil
}

