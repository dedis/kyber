package filippo_ed25519

import (
	"crypto/cipher"
<<<<<<< HEAD
	"encoding/hex"
	"errors"
	filippo_ed25519 "filippo.io/edwards25519"
	"fmt"
	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/kyber/v3/group/mod"
<<<<<<< HEAD
	"go.dedis.ch/kyber/v3/util/random"
	"io"
	"math/big"
)

type Scalar struct {
	scalar *filippo_ed25519.Scalar
}

func (s *Scalar) Equal(a kyber.Scalar) bool {
	return s.scalar.Equal(a.(*Scalar).scalar) == 1
}

func (s *Scalar) Set(a kyber.Scalar) kyber.Scalar {
	if s.scalar == nil {
		s.scalar = new(filippo_ed25519.Scalar)
	}
	_ = s.scalar.Set(a.(*Scalar).scalar)
	return s
}

func (s *Scalar) Clone() kyber.Scalar {
	s2 := new(Scalar)
	s2.scalar = new(filippo_ed25519.Scalar)
	s2.scalar.Set(s.scalar)
	return s2
}

func (s *Scalar) SetInt64(v int64) kyber.Scalar {
	return s.setInt(mod.NewInt64(v, primeOrder))
}

func (s *Scalar) Zero() kyber.Scalar {
	b := [32]byte{0}
	if s.scalar == nil {
		s.scalar = new(filippo_ed25519.Scalar)
	}
	_, err := s.scalar.SetCanonicalBytes(b[:])
	if err != nil {
		fmt.Println(err)
	}
	return s
}

func (s *Scalar) One() kyber.Scalar {
	b := [32]byte{1}
	if s.scalar == nil {
		s.scalar = new(filippo_ed25519.Scalar)
	}
	_, err := s.scalar.SetCanonicalBytes(b[:])
	if err != nil {
		fmt.Println(err)
	}
	return s
}

func (s *Scalar) Add(a, b kyber.Scalar) kyber.Scalar {
	if s.scalar == nil {
		s.scalar = new(filippo_ed25519.Scalar)
	}
	s.scalar.Add(a.(*Scalar).scalar, b.(*Scalar).scalar)
	return s
}

func (s *Scalar) Sub(a, b kyber.Scalar) kyber.Scalar {
	if s.scalar == nil {
		s.scalar = new(filippo_ed25519.Scalar)
	}
	s.scalar.Subtract(a.(*Scalar).scalar, b.(*Scalar).scalar)
	return s
}

func (s *Scalar) Mul(a, b kyber.Scalar) kyber.Scalar {
	if s.scalar == nil {
		s.scalar = new(filippo_ed25519.Scalar)
	}
	s.scalar.Multiply(a.(*Scalar).scalar, b.(*Scalar).scalar)
	return s
}

func (s *Scalar) Div(a, b kyber.Scalar) kyber.Scalar {
	if s.scalar == nil {
		s.scalar = new(filippo_ed25519.Scalar)
	}
	b1 := b.(*Scalar)
	b1.scalar.Invert(b1.scalar)
	s.scalar.Multiply(a.(*Scalar).scalar, b1.scalar)
	return s
}

func (s *Scalar) Inv(a kyber.Scalar) kyber.Scalar {
	if s.scalar == nil {
		s.scalar = new(filippo_ed25519.Scalar)
	}
	s.scalar.Invert(a.(*Scalar).scalar)
	return s
}

func (s *Scalar) Neg(a kyber.Scalar) kyber.Scalar {
	if s.scalar == nil {
		s.scalar = new(filippo_ed25519.Scalar)
	}
	s.scalar.Negate(a.(*Scalar).scalar)
	return s
}

func (s *Scalar) Pick(rand cipher.Stream) kyber.Scalar {
	i := mod.NewInt(random.Int(primeOrder, rand), primeOrder)
	return s.setInt(i)
}

func (s *Scalar) SetBytes(b []byte) kyber.Scalar {
	// This function requires bytes in little-endian
	if s.scalar == nil {
		s.scalar = new(filippo_ed25519.Scalar)
	}
	_, err := s.scalar.SetCanonicalBytes(b)
	if err != nil {
		fmt.Println(err)
	}
	return s
}

func (s *Scalar) setInt(i *mod.Int) kyber.Scalar {
	b := i.LittleEndian(32, 32)
	if s.scalar == nil {
		s.scalar = new(filippo_ed25519.Scalar)
	}
	_, err := s.scalar.SetCanonicalBytes(b)
	if err != nil {
		fmt.Println(err)
	}
	return s
}

func setBigInt(i *big.Int) *Scalar {
	s := Scalar{}
	s.setInt(mod.NewInt(i, fullOrder))
	return &s
}

func (s *Scalar) MarshalSize() int {
	return 32
}

func (s *Scalar) MarshalBinary() ([]byte, error) {
	if s.scalar == nil {
		return nil, errors.New("point not initialized")
	}
	b := s.scalar.Bytes()
	return b, nil
}

func (s *Scalar) UnmarshalBinary(b []byte) error {
	if s.scalar == nil {
		s.scalar = new(filippo_ed25519.Scalar)
	}
	_, err := s.scalar.SetCanonicalBytes(b)
	return err
}

func (s *Scalar) String() string {
	b, _ := s.MarshalBinary()
	return hex.EncodeToString(b)
}

func (s *Scalar) MarshalTo(w io.Writer) (int, error) {
	buf, err := s.MarshalBinary()
	if err != nil {
		return 0, err
	}
	return w.Write(buf)
}

func (s *Scalar) UnmarshalFrom(r io.Reader) (int, error) {
	if strm, ok := r.(cipher.Stream); ok {
		s.Pick(strm)
		return -1, nil // no byte-count when picking randomly
	}
	buf := make([]byte, s.MarshalSize())
	n, err := io.ReadFull(r, buf)
	if err != nil {
		return n, err
	}
	return n, s.UnmarshalBinary(buf)
=======
	"errors"
=======
>>>>>>> Filippo integration completed
	"go.dedis.ch/kyber/v3/util/random"
	"io"
	"math/big"
)

type Scalar struct {
	scalar *filippo_ed25519.Scalar
}

func (s *Scalar) Equal(a kyber.Scalar) bool {
	return s.scalar.Equal(a.(*Scalar).scalar) == 1
}

func (s *Scalar) Set(a kyber.Scalar) kyber.Scalar {
	if s.scalar == nil {
		s.scalar = new(filippo_ed25519.Scalar)
	}
	_ = s.scalar.Set(a.(*Scalar).scalar)
	return s
}

func (s *Scalar) Clone() kyber.Scalar {
	s2 := *s
	return &s2
}

func (s *Scalar) SetInt64(v int64) kyber.Scalar {
	return s.setInt(mod.NewInt64(v, primeOrder))
}

<<<<<<< HEAD
func (s *scalar) Add(a, b kyber.Scalar) kyber.Scalar {
	return nil
}

func (s *scalar) Clone() kyber.Scalar {
	return nil
}

func (s *scalar) Set(a kyber.Scalar) kyber.Scalar {
	return nil
=======
func (s *Scalar) Zero() kyber.Scalar {
	b := [32]byte{0}
	if s.scalar == nil {
		s.scalar = new(filippo_ed25519.Scalar)
	}
	_, err := s.scalar.SetCanonicalBytes(b[:])
	if err != nil {
		fmt.Println(err)
	}
	return s
}

func (s *Scalar) One() kyber.Scalar {
	b := [32]byte{1}
	if s.scalar == nil {
		s.scalar = new(filippo_ed25519.Scalar)
	}
	_, err := s.scalar.SetCanonicalBytes(b[:])
	if err != nil {
		fmt.Println(err)
	}
	return s
}

func (s *Scalar) Add(a, b kyber.Scalar) kyber.Scalar {
	if s.scalar == nil {
		s.scalar = new(filippo_ed25519.Scalar)
	}
	s.scalar.Add(a.(*Scalar).scalar, b.(*Scalar).scalar)
	return s
>>>>>>> Filippo integration completed
}

func (s *Scalar) Sub(a, b kyber.Scalar) kyber.Scalar {
	if s.scalar == nil {
		s.scalar = new(filippo_ed25519.Scalar)
	}
	s.scalar.Subtract(a.(*Scalar).scalar, b.(*Scalar).scalar)
	return s
}

func (s *Scalar) Mul(a, b kyber.Scalar) kyber.Scalar {
	if s.scalar == nil {
		s.scalar = new(filippo_ed25519.Scalar)
	}
	s.scalar.Multiply(a.(*Scalar).scalar, b.(*Scalar).scalar)
	return s
}

<<<<<<< HEAD
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
=======
func (s *Scalar) Div(a, b kyber.Scalar) kyber.Scalar {
	if s.scalar == nil {
		s.scalar = new(filippo_ed25519.Scalar)
	}
	b1 := b.(*Scalar)
	b1.scalar.Invert(b1.scalar)
	s.scalar.Multiply(a.(*Scalar).scalar, b1.scalar)
	return s
}

func (s *Scalar) Inv(a kyber.Scalar) kyber.Scalar {
	if s.scalar == nil {
		s.scalar = new(filippo_ed25519.Scalar)
	}
	s.scalar.Invert(a.(*Scalar).scalar)
	return s
}

func (s *Scalar) Neg(a kyber.Scalar) kyber.Scalar {
	if s.scalar == nil {
		s.scalar = new(filippo_ed25519.Scalar)
	}
	s.scalar.Negate(a.(*Scalar).scalar)
	return s
}

func (s *Scalar) Pick(rand cipher.Stream) kyber.Scalar {
>>>>>>> Filippo integration completed
	i := mod.NewInt(random.Int(primeOrder, rand), primeOrder)
	return s.setInt(i)
}

<<<<<<< HEAD
// SetBytes s to b, interpreted as a little endian integer.
func (s *scalar) SetBytes(b []byte) kyber.Scalar {
	return nil
=======
func (s *Scalar) SetBytes(b []byte) kyber.Scalar {
	// This function requires bytes in little-endian
	if s.scalar == nil {
		s.scalar = new(filippo_ed25519.Scalar)
	}
	_, err := s.scalar.SetCanonicalBytes(b)
	if err != nil {
		fmt.Println(err)
	}
	return s
>>>>>>> Filippo integration completed
}

func (s *Scalar) setInt(i *mod.Int) kyber.Scalar {
	b := i.LittleEndian(32, 32)
	if s.scalar == nil {
		s.scalar = new(filippo_ed25519.Scalar)
	}
	_, err := s.scalar.SetCanonicalBytes(b)
	if err != nil {
		fmt.Println(err)
	}
	return s
}

<<<<<<< HEAD
func (s *scalar) String() string {
	return ""
=======
func setBigInt(i *big.Int) *Scalar {
	s := Scalar{}
	s.setInt(mod.NewInt(i, fullOrder))
	return &s
>>>>>>> Filippo integration completed
}

func (s *Scalar) MarshalSize() int {
	return 32
}

func (s *Scalar) MarshalBinary() ([]byte, error) {
	if s.scalar == nil {
		s.scalar = new(filippo_ed25519.Scalar)
	}
	b := s.scalar.Bytes()
	return b, nil
}

func (s *Scalar) UnmarshalBinary(b []byte) error {
	if s.scalar == nil {
		return errors.New("scalar not initialized")
	}
	_, err := s.scalar.SetCanonicalBytes(b)
	return err
}

<<<<<<< HEAD
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
>>>>>>> Docs added and filippo integration initiated
=======
func (s *Scalar) String() string {
	b, _ := s.MarshalBinary()
	return hex.EncodeToString(b)
}

func (s *Scalar) MarshalTo(w io.Writer) (int, error) {
	buf, err := s.MarshalBinary()
	if err != nil {
		return 0, err
	}
	return w.Write(buf)
}

func (s *Scalar) UnmarshalFrom(r io.Reader) (int, error) {
	if strm, ok := r.(cipher.Stream); ok {
		s.Pick(strm)
		return -1, nil // no byte-count when picking randomly
	}
	buf := make([]byte, s.MarshalSize())
	n, err := io.ReadFull(r, buf)
	if err != nil {
		return n, err
	}
	return n, s.UnmarshalBinary(buf)
>>>>>>> Filippo integration completed
}
