// Package secp256k1 is an implementation of the kyber.{Group,Point,Scalcar}
// interfaces, based on btcd/btcec and kyber/group/mod
//
// XXX: NOT CONSTANT TIME!
package secp256k1

// Implementation of kyber.Scalar interface for arithmetic operations mod the
// order of the secpk256k1 group (i.e. hex value
// 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141.)

import (
	"crypto/cipher"
	"fmt"
	"io"
	"math/big"

	secp256k1BTCD "github.com/btcsuite/btcd/btcec"

	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/kyber/v3/util/random"
)

var groupOrder = secp256k1BTCD.S256().N

type secp256k1Scalar big.Int

// AllowVarTime, if passed true indicates that variable-time operations may be
// used on s.
func (s *secp256k1Scalar) AllowVarTime(varTimeAllowed bool) {
	// Since constant-time operations are unimplemented for secp256k1, a
	// value of false panics.
	if !varTimeAllowed {
		panic("implementation is not constant-time!")
	}
}

// newScalar returns a secpk256k1 scalar, with value v modulo groupOrder.
func newScalar(v *big.Int) kyber.Scalar {
	return (*secp256k1Scalar)(zero().Mod(v, groupOrder))
}

func zero() *big.Int { return big.NewInt(0) }

func toInt(s kyber.Scalar) *big.Int { return (*big.Int)(s.(*secp256k1Scalar)) }

func (s *secp256k1Scalar) int() *big.Int { return (*big.Int)(s) }

func (s *secp256k1Scalar) modG() kyber.Scalar {
	// TODO(alx): Make this faster
	s.int().Mod(s.int(), groupOrder)
	return s
}

func (s *secp256k1Scalar) String() string {
	return fmt.Sprintf("scalar{%x}", (*big.Int)(s))
}

var scalarZero = zero()

// Equal returns true if s and sPrime represent the same value modulo the group
// order, false otherwise
func (s *secp256k1Scalar) Equal(sPrime kyber.Scalar) bool {
	difference := zero().Sub(s.int(), toInt(sPrime))
	return scalarZero.Cmp(difference.Mod(difference, groupOrder)) == 0
}

// Set copies sPrime's value (modulo groupOrder) to s, and returns it
func (s *secp256k1Scalar) Set(sPrime kyber.Scalar) kyber.Scalar {
	return (*secp256k1Scalar)(s.int().Mod(toInt(sPrime), groupOrder))
}

// Clone returns a copy of s mod groupOrder
func (s *secp256k1Scalar) Clone() kyber.Scalar {
	return (*secp256k1Scalar)(zero().Mod(s.int(), groupOrder))
}

// SetInt64 returns s with value set to v modulo groupOrder
func (s *secp256k1Scalar) SetInt64(v int64) kyber.Scalar {
	return (*secp256k1Scalar)(s.int().SetInt64(v)) // NB: v < groupOrder
}

// Zero sets s to 0 mod groupOrder, and returns it
func (s *secp256k1Scalar) Zero() kyber.Scalar {
	return s.SetInt64(0)
}

// Add sets s to a+b mod groupOrder, and returns it
func (s *secp256k1Scalar) Add(a, b kyber.Scalar) kyber.Scalar {
	s.int().Add(toInt(a), toInt(b))
	return s.modG()
}

// Sub sets s to a-b mod groupOrder, and returns it
func (s *secp256k1Scalar) Sub(a, b kyber.Scalar) kyber.Scalar {
	s.int().Sub(toInt(a), toInt(b))
	return s.modG()
}

// Neg sets s to -s mod groupOrder, and returns it
func (s *secp256k1Scalar) Neg(a kyber.Scalar) kyber.Scalar {
	s.int().Neg(toInt(a))
	return s.modG()
}

// One sets s to 1 mod groupOrder, and returns it
func (s *secp256k1Scalar) One() kyber.Scalar {
	return s.SetInt64(1)
}

// Mul sets s to a*b mod groupOrder, and returns it
func (s *secp256k1Scalar) Mul(a, b kyber.Scalar) kyber.Scalar {
	// TODO(alx): Make this faster
	s.int().Mul(toInt(a), toInt(b))
	return s.modG()
}

// Div sets s to a*b⁻¹ mod groupOrder, and returns it
func (s *secp256k1Scalar) Div(a, b kyber.Scalar) kyber.Scalar {
	if toInt(b).Cmp(scalarZero) == 0 {
		panic("attempt to divide by zero")
	}
	// TODO(alx): Make this faster
	s.int().Mul(toInt(a), zero().ModInverse(toInt(b), groupOrder))
	return s.modG()
}

// Inv sets s to s⁻¹ mod groupOrder, and returns it
func (s *secp256k1Scalar) Inv(a kyber.Scalar) kyber.Scalar {
	if toInt(a).Cmp(scalarZero) == 0 {
		panic("attempt to divide by zero")
	}
	s.int().ModInverse(toInt(a), groupOrder)
	return s
}

// Pick sets s to a random value mod groupOrder sampled from rand, and returns
// it
func (s *secp256k1Scalar) Pick(rand cipher.Stream) kyber.Scalar {
	return s.Set((*secp256k1Scalar)(random.Int(groupOrder, rand)))
}

// MarshalBinary returns the big-endian byte representation of s, or an error on
// failure
func (s *secp256k1Scalar) MarshalBinary() ([]byte, error) {
	b := toInt(s.modG()).Bytes()
	// leftpad with zeros
	return append(make([]byte, s.MarshalSize()-len(b)), b...), nil
}

// MarshalSize returns the length of the byte representation of s
func (s *secp256k1Scalar) MarshalSize() int { return 32 }

// MarshalID returns the ID for a secp256k1 scalar
func (s *secp256k1Scalar) MarshalID() [8]byte {
	return [8]byte{'s', 'p', '2', '5', '6', '.', 's', 'c'}
}

// UnmarshalBinary sets s to the scalar represented by the contents of buf,
// returning error on failure.
func (s *secp256k1Scalar) UnmarshalBinary(buf []byte) error {
	if len(buf) != s.MarshalSize() {
		return fmt.Errorf(
			"cannot unmarshal to scalar: wrong length: %s", buf)
	}
	s.int().Mod(s.int().SetBytes(buf), groupOrder)
	return nil
}

// MarshalTo writes the serialized s to w, and returns the number of bytes
// written, or an error on failure.
func (s *secp256k1Scalar) MarshalTo(w io.Writer) (int, error) {
	buf, err := s.MarshalBinary()
	if err != nil {
		return 0, fmt.Errorf("cannot marshal binary: got '%s' from %x",
			err, s)
	}
	return w.Write(buf)
}

// UnmarshalFrom sets s to the scalar represented by bytes read from r, and
// returns the number of bytes read, or an error on failure.
func (s *secp256k1Scalar) UnmarshalFrom(r io.Reader) (int, error) {
	buf := make([]byte, s.MarshalSize())
	n, err := io.ReadFull(r, buf)
	if err != nil {
		return n, err
	}
	return n, s.UnmarshalBinary(buf)
}

// SetBytes sets s to the number with big-endian representation a mod
// groupOrder, and returns it
func (s *secp256k1Scalar) SetBytes(a []byte) kyber.Scalar {
	return (*secp256k1Scalar)(s.int().SetBytes(a))
}
