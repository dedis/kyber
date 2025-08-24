//go:build constantTime

// Package mod contains a generic implementation of finite field arithmetic
// on integer fields with a constant modulus.
package mod

import (
	"crypto/cipher"
	"encoding/hex"
	"errors"
	"go.dedis.ch/kyber/v4"
	"github.com/cronokirby/saferith"
	"go.dedis.ch/kyber/v4/compatible"
	"go.dedis.ch/kyber/v4/compatible/compatible_mod"
	"go.dedis.ch/kyber/v4/group/internal/marshalling"
	"go.dedis.ch/kyber/v4/util/random"
	"io"
)

var marshalScalarID = [8]byte{'m', 'o', 'd', '.', 'i', 'n', 't', ' '}

// Int is a generic implementation of finite field arithmetic
// on integer finite fields with a given constant modulus,
// built using Go's built-in big.Int or with the filosottile/bigmod package,
// depending on whether the constantTime build tag is chosen.
// Int satisfies the kyber.Scalar interface,
// and hence serves as a basic implementation of kyber.Scalar,
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
type Int struct {
	V  compatible.Int      // Integer value from 0 through M-1
	M  *compatible_mod.Mod // Modulus for finite field arithmetic
	BO kyber.ByteOrder     // Endianness which will be used on input and output
}

// SetString sets the Int to a rational fraction n/d represented by a pair of strings.
// If d == "", then the denominator is taken to be 1.
// Returns (i,true) on success, or
// (nil,false) if either string fails to parse.
func (i *Int) SetString(n, d string, base int) (*Int, bool) {
	if _, ok := i.V.SetStringM(n, i.M, base); !ok {
		return nil, false
	}
	if d != "" {
		var di Int
		di.M = i.M
		if _, ok := di.SetString(d, "", base); !ok {
			return nil, false
		}
		i.Div(i, &di)
	}
	return i, true
}

// Not used in constant time
//// Jacobi computes the Jacobi symbol of (a/M), which indicates whether a is
//// zero (0), a positive square in M (1), or a non-square in M (-1).
//func (i *Int) Jacobi(as kyber.Scalar) kyber.Scalar {
//	ai := as.(*Int) //nolint:errcheck // Design pattern to emulate generics
//	i.M = ai.M
//	i.V.SetUint(uint(big.Jacobi(&ai.V, i.M)))
//	return i
//}

// NewInt creates a new Int with a given compatible.Int and a compatible.Int modulus.
func NewInt(v *compatible.Int, m *compatible_mod.Mod) *Int {
	return new(Int).Init(v, m)
}

// NewInt64 creates a new Int with a given int64 value and bigmod.Mod modulus.
func NewInt64(v int64, m *compatible_mod.Mod) *Int {
	return new(Int).Init64(v, m)
}

// NewIntBytes creates a new Int with a given slice of bytes and a compatible.Int
// modulus.
func NewIntBytes(a []byte, m *compatible_mod.Mod, byteOrder kyber.ByteOrder) *Int {
	return new(Int).InitBytes(a, m, byteOrder)
}

// NewIntString creates a new Int with a given string and a compatible.Int modulus.
// The value is set to a rational fraction n/d in a given base.
func NewIntString(n, d string, base int, m *compatible_mod.Mod) *Int {
	return new(Int).InitString(n, d, base, m)
}

// Init a Int with a given compatible.Int value and modulus pointer.
// Note that the value is copied; the modulus is not.
func (i *Int) Init(v *compatible.Int, m *compatible_mod.Mod) *Int {
	i.M = m
	i.BO = kyber.BigEndian
	i.V = *compatible.NewInt(0).Mod(v, m)

	return i
}

// Init64 creates an Int with an int64 value and compatible.Int modulus.
func (i *Int) Init64(v int64, m *compatible_mod.Mod) *Int {
	// leaks the initialization sign, but the result will be positive anyway...
	i.M = m
	i.BO = kyber.BigEndian
	if v < 0 {
		i.V = *compatible.FromNat(i.M.Nat())
		negated := compatible.NewInt(-v)
		i.V = *compatible.NewInt(0).Sub(&i.V, negated, i.M)
	} else {
		i.V = *compatible.NewInt(0).SetUint(uint(v))
		i.V = *compatible.NewInt(0).Mod(&i.V, m)
	}
	return i
}

// InitBytes init the Int to a number represented in a big-endian byte string.
func (i *Int) InitBytes(a []byte, m *compatible_mod.Mod, byteOrder kyber.ByteOrder) *Int {
	i.M = m
	i.BO = byteOrder
	i.SetBytes(a)
	return i
}

// InitString inits the Int to a rational fraction n/d
// specified with a pair of strings in a given base.
func (i *Int) InitString(n, d string, base int, m *compatible_mod.Mod) *Int {
	i.M = m
	i.BO = kyber.BigEndian
	if _, ok := i.SetString(n, d, base); !ok {
		panic("InitString: invalid fraction representation")
	}
	return i
}

// Return the Int's integer value in hexadecimal string representation.
func (i *Int) String() string {
	return hex.EncodeToString(i.V.Bytes(i.M))
}

// SetString sets the Int to a rational fraction n/d represented by a pair of strings.
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

// Jacobi computes the Jacobi symbol of (a/M), which indicates whether a is
// zero (0), a positive square in M (1), or a non-square in M (-1).
func (i *Int) Jacobi(as kyber.Scalar) kyber.Scalar {
	ai := as.(*Int) //nolint:errcheck // Design pattern to emulate generics
	i.M = ai.M
	i.V.SetUint64(uint64(big.Jacobi(&ai.V, i.M)))
	return i
}

// Cmp compares two Ints for equality or inequality
func (i *Int) Cmp(s2 kyber.Scalar) int {
	return i.V.Cmp(&s2.(*Int).V)
	//
	//
	//bigger, _, less := i.V.Cmp(s2.(*Int).V)
	//nat := new(compatible.Int).SetUint64(1)
	//nat.CondAssign(bigger, new(compatible.Int).SetUint64(2))
	//nat.CondAssign(less, new(compatible.Int).SetUint64(0))
	//return int(nat.Uint64()) - 1
}

// Equal returns true if the two Ints are equal
func (i *Int) Equal(s2 kyber.Scalar) bool {
	return i.V.Equal(&s2.(*Int).V)
}

// Nonzero returns true if the integer value is nonzero.
func (i *Int) Nonzero() bool {
	return i.V.IsZero() == false
}

// Set both value and modulus to be equal to another Int.
// Since this method copies the modulus as well,
// it may be used as an alternative to Init().
func (i *Int) Set(a kyber.Scalar) kyber.Scalar {
	ai := a.(*Int) //nolint:errcheck // Design pattern to emulate generics
	i.M = ai.M
	i.V = *i.V.Set(&ai.V)
	return i
}

// Clone returns a separate duplicate of this Int.
func (i *Int) Clone() kyber.Scalar {
	ni := new(Int).Init(&i.V, i.M)
	ni.BO = i.BO
	return ni
}

// Zero set the Int to the value 0.  The modulus must already be initialized.
func (i *Int) Zero() kyber.Scalar {
	i.V = *compatible.NewInt(0)
	return i
}

// One sets the Int to the value 1.  The modulus must already be initialized.
func (i *Int) One() kyber.Scalar {
	i.V = *compatible.NewInt(1)
	return i
}

// SetInt64 sets the Int to an arbitrary 64-bit "small integer" value.
// The modulus must already be initialized.
func (i *Int) SetInt64(v int64) kyber.Scalar {
	if v < 0 {
		panic("negative value")
	}
	i.V = *compatible.NewInt(0).Mod(compatible.NewInt(v), i.M)

	return i
}

// SetUint64 sets the Int to an arbitrary uint64 value.
// The modulus must already be initialized.
func (i *Int) SetUint64(v uint64) kyber.Scalar {
	i.V.Mod(compatible.NewUint(v), i.M)
	return i
}

//
//// Uint64 returns the uint64 representation of the value.
//// If the value is not representable in an uint64 the result is undefined.
//func (i *Int) Uint64() uint64 {
//	return i.V.()
//}

// Add sets the target to a + b mod M, where M is a's modulus..
func (i *Int) Add(a, b kyber.Scalar) kyber.Scalar {
	ai := a.(*Int) //nolint:errcheck // Design pattern to emulate generics
	bi := b.(*Int) //nolint:errcheck // Design pattern to emulate generics
	i.M = ai.M
	i.V = *compatible.NewInt(0).Add(&ai.V, &bi.V, i.M)
	return i
}

// Sub sets the target to a - b mod M.
// Target receives a's modulus.
func (i *Int) Sub(a, b kyber.Scalar) kyber.Scalar {
	ai := a.(*Int) //nolint:errcheck // Design pattern to emulate generics
	bi := b.(*Int) //nolint:errcheck // Design pattern to emulate generics
	i.M = ai.M
	i.V = *compatible.NewInt(0).Sub(&ai.V, &bi.V, i.M)
	return i
}

// Neg sets the target to -a mod M.
func (i *Int) Neg(a kyber.Scalar) kyber.Scalar {
	newNat := new(compatible.Int)
	ai := a.(*Int)
	newNat.Int = *ai.M.Nat()
	i.V.Set(newNat)
	i.M = ai.M
	i.V = *compatible.NewInt(0).Sub(&i.V, &ai.V, i.M)

	//ai := a.(*Int) //nolint:errcheck // Design pattern to emulate generics
	//i.M = ai.M
	//if ai.V.Sign() > 0 {
	//	i.V.Sub(i.M, &ai.V)
	//} else {
	//	i.V.SetUint64(0)
	//}
	return i
}

// Mul sets the target to a * b mod M.
// Target receives a's modulus.
func (i *Int) Mul(a, b kyber.Scalar) kyber.Scalar {
	ai := a.(*Int) //nolint:errcheck // Design pattern to emulate generics
	bi := b.(*Int) //nolint:errcheck // Design pattern to emulate generics
	i.M = ai.M
	i.V = *compatible.NewInt(1).Mul(&ai.V, &bi.V, ai.M)

	return i
}

// Div sets the target to a * b^-1 mod M, where b^-1 is the modular inverse of b.
func (i *Int) Div(a, b kyber.Scalar) kyber.Scalar {
	ai := a.(*Int) //nolint:errcheck // Design pattern to emulate generics
	bi := b.(*Int) //nolint:errcheck // Design pattern to emulate generics

	inverse := NewInt(compatible.NewInt(0), bi.M).Inv(bi)
	divResult := i.Mul(ai, inverse)
	// todo temporary solution... i.Set(divResult) does not work.........
	i.V = divResult.(*Int).V
	return i
}

// Inv sets the target to the modular inverse of a with respect to modulus M.
func (i *Int) Inv(a kyber.Scalar) kyber.Scalar {
	ai := a.(*Int) //nolint:errcheck // Design pattern to emulate generics
	i.M = ai.M
	i.V = *compatible.NewInt(0).ModInverse(&a.(*Int).V, i.M)
	return i
}

// Exp sets the target to a^e mod M,
// where e is an arbitrary compatible.Int exponent (not necessarily 0 <= e < M).
func (i *Int) Exp(a kyber.Scalar, e *compatible.Int) kyber.Scalar {
	ai := a.(*Int) //nolint:errcheck // Design pattern to emulate generics
	i.M = ai.M
	// to protect against golang/go#22830
	var tmp = new(compatible.Int)
	tmp.Exp(&ai.V, e, i.M)
	i.V = *tmp
	return i
}

//not used in constant time
//// Sqrt computes some square root of a mod M of one exists.
//// Assumes the modulus M is an odd prime.
//// Returns true on success, false if input a is not a square.
//func (i *Int) Sqrt(as kyber.Scalar) bool {
//	ai := as.(*Int) //nolint:errcheck // Design pattern to emulate generics
//	out := i.V.ModSqrt(ai.V, ai.M)
//	i.M = ai.M
//	return out != nil
//}

// Pick a [pseudo-]random integer, modulo M,
// using bits from the given stream cipher.
func (i *Int) Pick(rand cipher.Stream) kyber.Scalar {
	modulusBig := i.M.ToBigInt()

	randomBig := random.Int(modulusBig, rand)

	i.V = *compatible.FromBigInt(randomBig, i.M)
	return i
}

// ByteOrder return the byte representation type (big or little endian)
func (i *Int) ByteOrder() kyber.ByteOrder {
	return i.BO
}

// GroupOrder returns the order of the underlying group
func (i *Int) GroupOrder() *big.Int {
	return big.NewInt(0).Set(i.M.Modulus)
}

// MarshalSize returns the length in bytes of encoded integers with modulus M.
// The length of encoded Ints depends only on the size of the modulus,
// and not on the the value of the encoded integer,
// making the encoding is fixed-length for simplicity and security.
func (i *Int) MarshalSize() int {
	return (i.M.BitLen() + 7) / 8
}

// MarshalBinary encodes the value of this Int into a byte-slice exactly Len() bytes long.
// It uses i's ByteOrder to determine which byte order to output.
func (i *Int) MarshalBinary() ([]byte, error) {
	l := i.MarshalSize()
	b := i.V.Bytes(i.M) // may be shorter than l
	offset := l - len(b)

	if i.BO == kyber.LittleEndian {
		return i.LittleEndian(l, l), nil
	}

	if offset != 0 {
		nb := make([]byte, l)
		copy(nb[offset:], b)
		b = nb
	}
	return b, nil
}

// MarshalID returns a unique identifier for this type
func (i *Int) MarshalID() [8]byte {
	return marshalScalarID
}

// UnmarshalBinary tries to decode a Int from a byte-slice buffer.
// Returns an error if the buffer is not exactly Len() bytes long
// or if the contents of the buffer represents an out-of-range integer.
func (i *Int) UnmarshalBinary(buf []byte) error {
	if len(buf) != i.MarshalSize() {
		return errors.New("UnmarshalBinary: wrong size buffer")
	}
	// Still needed here because of the comparison with the modulo
	if i.BO == kyber.LittleEndian {
		buf = reverse(nil, buf)
	}
	i.V.SetBytes(buf, i.M)
	return nil
}

// MarshalTo encodes this Int to the given Writer.
func (i *Int) MarshalTo(w io.Writer) (int, error) {
	return marshalling.ScalarMarshalTo(i, w)
}

// UnmarshalFrom tries to decode an Int from the given Reader.
func (i *Int) UnmarshalFrom(r io.Reader) (int, error) {
	return marshalling.ScalarUnmarshalFrom(i, r)
}

// BigEndian encodes the value of this Int into a big-endian byte-slice
// at least min bytes but no more than max bytes long.
// Panics if max != 0 and the Int cannot be represented in max bytes.
func (i *Int) BigEndian(minBytes, maxBytes int) []byte {
	act := i.MarshalSize()
	pad, ofs := act, 0
	if pad < minBytes {
		pad, ofs = minBytes, minBytes-act
	}
	if maxBytes != 0 && pad > maxBytes {
		panic("Int not representable in max bytes")
	}
	buf := make([]byte, pad)
	i.V.FillBytes(buf[ofs:])
	return buf
}

// SetBytes set the value value to a number represented
// by a byte string.
// Endianness depends on the endianess set in i.
func (i *Int) SetBytes(a []byte) kyber.Scalar {
	var buff = a
	if i.BO == kyber.LittleEndian {
		buff = reverse(nil, a)
	}
	i.V.SetBytes(buff, i.M)
	return i
}

// LittleEndian encodes the value of this Int into a little-endian byte-slice
// at least min bytes but no more than max bytes long.
// Panics if max != 0 and the Int cannot be represented in max bytes.
func (i *Int) LittleEndian(minByte, maxBytes int) []byte {
	act := i.MarshalSize()
	vBytes := i.V.Bytes(i.M)
	vSize := len(vBytes)
	if vSize < act {
		act = vSize
	}
	pad := act
	if pad < minByte {
		pad = minByte
	}
	if maxBytes != 0 && pad > maxBytes {
		panic("Int not representable in max bytes")
	}
	buf := make([]byte, pad)
	// todo, check if this must be changed for constant-time execution
	reverse(buf[:act], vBytes)
	return buf
}

// reverse copies src into dst in byte-reversed order and returns dst,
// such that src[0] goes into dst[len-1] and vice versa.
// dst and src may be the same slice but otherwise must not overlap.
func reverse(dst, src []byte) []byte {
	if dst == nil {
		dst = make([]byte, len(src))
	}
	l := len(dst)
	for i, j := 0, l-1; i < (l+1)/2; {
		dst[i], dst[j] = src[j], src[i]
		i++
		j--
	}
	return dst
}
