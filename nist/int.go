package nist

import (
	"crypto/cipher"
	"encoding/hex"
	"errors"
	"github.com/dedis/crypto/group"
	"github.com/dedis/crypto/math"
	"github.com/dedis/crypto/random"
	"github.com/dedis/crypto/util"
	"golang.org/x/net/context"
	"io"
	"math/big"
)

var zero = big.NewInt(0)
var one = big.NewInt(1)
var two = big.NewInt(2)

// Int is a generic implementation of finite field arithmetic
// on integer finite fields with a given constant modulus,
// built using Go's built-in big.Int package.
// Int satisfies the abstract group.Element interface,
// and hence serves as a basic implementation of group.Element,
// e.g., representing discrete-log exponents of Schnorr groups
// or scalar multipliers for elliptic curves.
//
// Int offers an API similar to and compatible with big.Int,
// but "carries around" a pointer to the relevant modulus
// and automatically normalizes the value to that modulus
// after all arithmetic operations, simplifying modular arithmetic.
// Binary operations assume that the source(s)
// have the same modulus, but do not check this assumption.
// Unary and binary arithmetic operations may be performed on uninitialized
// target objects, and receive the modulus of the first operand.
// For efficiency the modulus field M is a pointer,
// whose target is assumed never to change.
//
// XXX rename IntElement or something like that?
type Int struct {
	V big.Int  // Integer value from 0 through M-1
	M *big.Int // Modulus for finite field arithmetic
}

// Create a new Int with a given int64 value and big.Int modulus.
func NewInt(v int64, M *big.Int) *Int {
	return new(Int).Init64(v, M)
}

// Create a new Int with the same modulus as an existing one.
func (i *Int) New() group.Element {
	return &Int{big.Int{}, i.M}
}

// Initialize a Int with a given big.Int value and modulus pointer.
// Note that the value is copied; the modulus is not.
func (i *Int) Init(V *big.Int, M *big.Int) *Int {
	i.M = M
	i.V.Set(V).Mod(&i.V, M)
	return i
}

// Initialize a Int with an int64 value and big.Int modulus.
func (i *Int) Init64(v int64, M *big.Int) *Int {
	i.M = M
	i.V.SetInt64(v).Mod(&i.V, M)
	return i
}

// Initializa to a number represented in a big-endian byte string.
func (i *Int) InitBytes(a []byte, M *big.Int) *Int {
	i.M = M
	i.V.SetBytes(a).Mod(&i.V, i.M)
	return i
}

// Initialize a Int to a rational fraction n/d
// specified with a pair of strings in a given base.
func (i *Int) InitString(n, d string, base int, M *big.Int) *Int {
	i.M = M
	if _, succ := i.SetString(n, d, base); !succ {
		panic("InitString: invalid fraction representation")
	}
	return i
}

// Return the Int's integer value in decimal string representation.
func (i *Int) String() string {
	return hex.EncodeToString(i.V.Bytes())
}

// Set value to a rational fraction n/d represented by a pair of strings.
// If d == "", then the denominator is taken to be 1.
// Returns (i,true) on success, or
// (nil,false) if either string fails to parse.
func (i *Int) SetString(n, d string, base int) (*Int, bool) {
	if _, succ := i.V.SetString(n, base); !succ {
		return nil, false
	}
	if d != "" {
		var di Int
		di.M = i.M
		if _, succ := di.SetString(d, "", base); !succ {
			return nil, false
		}
		i.Div(i, &di)
	}
	return i, true
}

// Compare two Ints for equality or inequality
func (i *Int) Cmp(s2 group.Element) int {
	return i.V.Cmp(&s2.(*Int).V)
}

// Test two Ints for equality
func (i *Int) Equal(s2 group.Element) bool {
	return i.V.Cmp(&s2.(*Int).V) == 0
}

// Returns true if the integer value is nonzero.
func (i *Int) Nonzero() bool {
	return i.V.Sign() != 0
}

// Set both value and modulus to be equal to another Int.
// Since this method copies the modulus as well,
// it may be used as an alternative to Init().
func (i *Int) Set(a group.Element) group.Element {
	ai := a.(*Int)
	i.V.Set(&ai.V)
	i.M = ai.M
	return i
}

// Set value to a number represented in a big-endian byte string.
func (i *Int) SetBytes(a []byte) *Int {
	i.V.SetBytes(a).Mod(&i.V, i.M)
	return i
}

// Set value to a number represented in a little-endian byte string.
func (i *Int) SetLittleEndian(a []byte) *Int {
	be := make([]byte, len(a))
	util.Reverse(be, a)
	i.V.SetBytes(be).Mod(&i.V, i.M)
	return i
}

// Set to the value 0.  The modulus must already be initialized.
func (i *Int) Zero() group.Element {
	i.V.SetInt64(0)
	return i
}

// Set to the value 1.  The modulus must already be initialized.
func (i *Int) One() group.Element {
	i.V.SetInt64(1)
	return i
}

// Set to an arbitrary big.Int value.
// The modulus must already be initialized.
func (i *Int) SetInt(v *big.Int) group.FieldElement {
	i.V.Set(v).Mod(&i.V, i.M)
	return i
}

// Set to an arbitrary 64-bit "small integer" value.
// The modulus must already be initialized.
func (i *Int) SetInt64(v int64) group.FieldElement {
	i.V.SetInt64(v).Mod(&i.V, i.M)
	return i
}

// Return the int64 representation of the value.
// If the value is not representable in an int64 the result is undefined.
func (i *Int) Int64() int64 {
	return i.V.Int64()
}

// Set to an arbitrary uint64 value.
// The modulus must already be initialized.
func (i *Int) SetUint64(v uint64) group.Element {
	i.V.SetUint64(v).Mod(&i.V, i.M)
	return i
}

// Return the uint64 representation of the value.
// If the value is not representable in an uint64 the result is undefined.
func (i *Int) Uint64() uint64 {
	return i.V.Uint64()
}

// Set target to a + b mod M, where M is a's modulus..
func (i *Int) Add(a, b group.Element) group.Element {
	ai := a.(*Int)
	bi := b.(*Int)
	i.M = ai.M
	i.V.Add(&ai.V, &bi.V).Mod(&i.V, i.M)
	return i
}

// Set target to a - b mod M.
// Target receives a's modulus.
func (i *Int) Sub(a, b group.Element) group.Element {
	ai := a.(*Int)
	bi := b.(*Int)
	i.M = ai.M
	i.V.Sub(&ai.V, &bi.V).Mod(&i.V, i.M)
	return i
}

// Set to -a mod M.
func (i *Int) Neg(a group.Element) group.Element {
	ai := a.(*Int)
	i.M = ai.M
	if ai.V.Sign() > 0 {
		i.V.Sub(i.M, &ai.V)
	} else {
		i.V.SetUint64(0)
	}
	return i
}

// Set to a * b mod M.
// Target receives a's modulus.
func (i *Int) Mul(a, b group.Element) group.Element {
	ai := a.(*Int)
	bi := b.(*Int)
	i.M = ai.M
	i.V.Mul(&ai.V, &bi.V).Mod(&i.V, i.M)
	return i
}

// Set to a * b^-1 mod M, where b^-1 is the modular inverse of b.
func (i *Int) Div(a, b group.Element) group.FieldElement {
	ai := a.(*Int)
	bi := b.(*Int)
	var t big.Int
	i.M = ai.M
	i.V.Mul(&ai.V, t.ModInverse(&bi.V, i.M))
	i.V.Mod(&i.V, i.M)
	return i
}

// Set to the modular inverse of a with respect to modulus M.
func (i *Int) Inv(a group.Element) group.FieldElement {
	ai := a.(*Int)
	i.M = ai.M
	i.V.ModInverse(&a.(*Int).V, i.M)
	return i
}

// Set to a^e mod M,
// where e is an arbitrary big.Int exponent (not necessarily 0 <= e < M).
func (i *Int) Exp(a group.Element, e *big.Int) group.Element {
	ai := a.(*Int)
	i.M = ai.M
	i.V.Exp(&ai.V, e, i.M)
	return i
}

// Compute the Legendre symbol of i, if modulus M is prime,
// using the Euler criterion (which involves exponentiation).
func (i *Int) legendre() int {
	var Pm1, v big.Int
	Pm1.Sub(i.M, one)
	v.Div(&Pm1, two)
	v.Exp(&i.V, &v, i.M)
	if v.Cmp(&Pm1) == 0 {
		return -1
	}
	return v.Sign()
}

// Set to the Jacobi symbol of (a/M), which indicates whether a is
// zero (0), a positive square in M (1), or a non-square in M (-1).
func (i *Int) Jacobi(as group.Element) {
	ai := as.(*Int)
	i.M = ai.M
	i.V.SetInt64(int64(math.Jacobi(&ai.V, i.M)))
}

// Compute some square root of a mod M of one exists.
// Assumes the modulus M is an odd prime.
// Returns true on success, false if input a is not a square.
// (This really should be part of Go's big.Int library.)
func (i *Int) Sqrt(as group.Element) bool {
	ai := as.(*Int)
	i.M = ai.M
	return math.Sqrt(&i.V, &ai.V, ai.M)
}

// Pick a [pseudo-]random integer modulo M
// using bits from the given stream cipher.
func (i *Int) Pick(data []byte, rand cipher.Stream) []byte {
	i.V.Set(random.Int(i.M, rand))
	return data
}

// Return the number of data bytes that can be reliably embedded.
// Int elements currently don't support data embedding
// (but might in the future).
func (i *Int) PickLen() int {
	return 0
}

// Extract embedded data
func (i *Int) Data() ([]byte, error) {
	panic("Int doesn't support embedding") // XXX it easily could!
}

// Return the length in bytes of encoded integers with modulus M.
// The length of encoded Ints depends only on the size of the modulus,
// and not on the the value of the encoded integer,
// making the encoding is fixed-length for simplicity and security.
func (i *Int) MarshalSize() int {
	return (i.M.BitLen() + 7) / 8
}

// Encode the value of this Int into a byte-slice exactly Len() bytes long.
func (i *Int) MarshalBinary() ([]byte, error) {
	l := i.MarshalSize()
	b := i.V.Bytes() // may be shorter than l
	if ofs := l - len(b); ofs != 0 {
		nb := make([]byte, l)
		copy(nb[ofs:], b)
		return nb, nil
	}
	return b, nil
}

// Attempt to decode a Int from a byte-slice buffer.
// Returns an error if the buffer is not exactly Len() bytes long
// or if the contents of the buffer represents an out-of-range integer.
func (i *Int) UnmarshalBinary(buf []byte) error {
	if len(buf) != i.MarshalSize() {
		return errors.New("Int.Decode: wrong size buffer")
	}
	i.V.SetBytes(buf)
	if i.V.Cmp(i.M) >= 0 {
		return errors.New("Int.Decode: value out of range")
	}
	return nil
}

func (i *Int) Marshal(c context.Context, w io.Writer) (int, error) {
	return group.Marshal(c, i, w)
}

func (i *Int) Unmarshal(c context.Context, r io.Reader) (int, error) {
	return group.Unmarshal(c, i, r)
}

// Encode the value of this Int into a big-endian byte-slice
// at least min bytes but no more than max bytes long.
// Panics if max != 0 and the Int cannot be represented in max bytes.
func (i *Int) BigEndian(min, max int) []byte {
	act := i.MarshalSize()
	pad, ofs := act, 0
	if pad < min {
		pad, ofs = min, min-act
	}
	if max != 0 && pad > max {
		panic("Int not representable in max bytes")
	}
	buf := make([]byte, pad)
	copy(buf[ofs:], i.V.Bytes())
	return buf
}

// Encode the value of this Int into a little-endian byte-slice
// at least min bytes but no more than max bytes long.
// Panics if max != 0 and the Int cannot be represented in max bytes.
func (i *Int) LittleEndian(min, max int) []byte {
	act := i.MarshalSize()
	pad := act
	if pad < min {
		pad = min
	}
	if max != 0 && pad > max {
		panic("Int not representable in max bytes")
	}
	buf := make([]byte, pad)
	util.Reverse(buf[:act], i.V.Bytes())
	return buf
}

// Return the length in bytes of a uniform byte-string encoding of this Int,
// satisfying the requirements of the Hiding interface.
// For a Int this is always the same length as the normal encoding.
func (i *Int) HideLen() int {
	return i.MarshalSize()
}

// HideEncode a Int such that it appears indistinguishable
// from a HideLen()-byte string chosen uniformly at random,
// assuming the Int contains a uniform integer modulo M.
// For a Int this always succeeds and returns non-nil.
func (i *Int) HideEncode(rand cipher.Stream) []byte {

	// Lengh of required encoding
	hidelen := i.HideLen()

	// Bit-position of the most-significant bit of the modular integer
	// in the most-significant byte of its encoding.
	highbit := uint((i.M.BitLen() - 1) & 7)

	var enc big.Int
	for {
		// Pick a random multiplier of a suitable bit-length.
		var b [1]byte
		rand.XORKeyStream(b[:], b[:])
		mult := int64(b[0] >> highbit)

		// Multiply, and see if we end up with
		// a Int of the proper byte-length.
		// Reroll if we get a result larger than HideLen(),
		// to ensure uniformity of the resulting encoding.
		enc.SetInt64(mult).Mul(&i.V, &enc)
		if enc.BitLen() <= hidelen*8 {
			break
		}
	}

	b := enc.Bytes() // may be shorter than l
	if ofs := hidelen - len(b); ofs != 0 {
		b = append(make([]byte, ofs), b...)
	}
	return b
}

// HideDecode a uniform representation of this object from a slice,
// whose length must be exactly HideLen().
func (i *Int) HideDecode(buf []byte) {
	if len(buf) != i.HideLen() {
		panic("Int.HideDecode: wrong size buffer")
	}
	i.V.SetBytes(buf)
	i.V.Mod(&i.V, i.M)
}
