package filippo_ed25519

import (
	"crypto/cipher"
	"errors"
	"go.dedis.ch/kyber/v3/util/random"
	"io"
	"math/big"

	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/kyber/v3/group/internal/marshalling"

	"go.dedis.ch/kyber/v3/group/mod"

	filippo_ed25519 "filippo.io/edwards25519"
)

var primeOrder, _ = new(big.Int).SetString("7237005577332262213973186563042994240857116359379907606001950938285454250989", 10)
var cofactor = new(big.Int).SetInt64(8)

var primeOrderScalar = newScalarInt(primeOrder)
var cofactorScalar = newScalarInt(cofactor)
var fullOrder = new(big.Int).Mul(primeOrder, cofactor)

type scalar struct {
	v [32]byte
}

func (s *scalar) MarshalBinary() ([]byte, error) {
	return s.toInt().MarshalBinary()
}

func (s *scalar) toInt() *mod.Int {
	return mod.NewIntBytes(s.v[:], primeOrder, mod.LittleEndian)
}

func (s *scalar) Add(a, b kyber.Scalar) kyber.Scalar {
	return nil
}

func (s *scalar) Clone() kyber.Scalar {
	return nil
}

func (s *scalar) Set(a kyber.Scalar) kyber.Scalar {
	return nil
}

func (s *scalar) setInt(i *mod.Int) kyber.Scalar {
	b := i.LittleEndian(32, 32)
	copy(s.v[:], b)
	return s
}

func (s *scalar) SetInt64(v int64) kyber.Scalar {
	return s.setInt(mod.NewInt64(v, primeOrder))
}

func (s *scalar) Zero() kyber.Scalar {
	return nil
}

func (s *scalar) One() kyber.Scalar {
	return nil
}

// Set to the modular difference a - b
func (s *scalar) Sub(a, b kyber.Scalar) kyber.Scalar {
	return nil
}

// Set to the modular negation of scalar a
func (s *scalar) Neg(a kyber.Scalar) kyber.Scalar {
	return nil
}

// Set to the modular product of scalars a and b
func (s *scalar) Mul(a, b kyber.Scalar) kyber.Scalar {
	v1, _ := a.(*scalar).MarshalBinary()
	fs1, _ := filippo_ed25519.NewScalar().SetCanonicalBytes(v1)
	v2, _ := b.(*scalar).MarshalBinary()
	fs2, _ := filippo_ed25519.NewScalar().SetCanonicalBytes(v2)
	ans := filippo_ed25519.NewScalar().Multiply(fs1, fs2)
	ansBytes := ans.Bytes()
	s.UnmarshalBinary(ansBytes)
	return nil
}

//// Set to the modular product of scalars a and b
//func (s *scalar) Mul(a, b kyber.Scalar) kyber.Scalar {
//	//v1, _ := a.(*scalar).MarshalBinary()
//	v1 := []byte{228, 18, 55, 134, 190, 242, 192, 219, 177, 65, 114, 168, 78, 91, 204, 217, 160, 227, 76, 150, 225, 232, 176, 219, 181, 192, 231, 118, 191, 149, 81, 6}
//	fs1, _ := filippo_ed25519.NewScalar().SetCanonicalBytes(v1)
//	//v2, _ := b.(*scalar).MarshalBinary()
//	v2 := []byte{185, 245, 238, 104, 148, 6, 24, 1, 163, 95, 113, 121, 119, 3, 81, 165, 37, 62, 28, 105, 224, 209, 167, 61, 108, 54, 185, 65, 49, 109, 105, 10}
//	fs2, _ := filippo_ed25519.NewScalar().SetCanonicalBytes(v2)
//	ans := filippo_ed25519.NewScalar().Multiply(fs1, fs2)
//	_ = ans
//	//ansBytes := ans.Bytes()
//	//s.UnmarshalBinary(ansBytes)
//	return nil
//}

// Set to the modular division of scalar a by scalar b
func (s *scalar) Div(a, b kyber.Scalar) kyber.Scalar {
	return nil
}

// Set to the modular inverse of scalar a
func (s *scalar) Inv(a kyber.Scalar) kyber.Scalar {
	return nil
}

func (s *scalar) Pick(rand cipher.Stream) kyber.Scalar {
	i := mod.NewInt(random.Int(primeOrder, rand), primeOrder)
	return s.setInt(i)
}

// SetBytes s to b, interpreted as a little endian integer.
func (s *scalar) SetBytes(b []byte) kyber.Scalar {
	return nil
}

// Encoded length of this object in bytes.
func (s *scalar) MarshalSize() int {
	return 32
}

func (s *scalar) String() string {
	return ""
}

func (s *scalar) MarshalTo(w io.Writer) (int, error) {
	return marshalling.ScalarMarshalTo(s, w)
}

func (s *scalar) UnmarshalFrom(r io.Reader) (int, error) {
	return marshalling.ScalarUnmarshalFrom(s, r)
}

// UnmarshalBinary reads the binary representation of a scalar.
func (s *scalar) UnmarshalBinary(buf []byte) error {
	if len(buf) != 32 {
		return errors.New("wrong size buffer")
	}
	copy(s.v[:], buf)
	return nil
}

// Equality test for two Scalars derived from the same Group
func (s *scalar) Equal(s2 kyber.Scalar) bool {
	v1, _ := (*s).MarshalBinary()
	fs1, _ := filippo_ed25519.NewScalar().SetCanonicalBytes(v1)
	v2, _ := s2.(*scalar).MarshalBinary()
	fs2, _ := filippo_ed25519.NewScalar().SetCanonicalBytes(v2)
	return fs1.Equal(fs2) == 1
}

func newScalarInt(i *big.Int) *scalar {
	s := scalar{}
	s.setInt(mod.NewInt(i, fullOrder))
	return &s
}
