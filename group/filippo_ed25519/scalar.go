package filippo_ed25519

import (
	"crypto/cipher"
	"encoding/hex"
	"errors"
	filippo_ed25519 "filippo.io/edwards25519"
	"fmt"
	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/kyber/v3/group/mod"
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
}
