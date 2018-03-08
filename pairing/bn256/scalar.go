package bn256

import (
	"crypto/cipher"
	"crypto/subtle"
	"errors"
	"io"
	"math/big"

	"github.com/dedis/kyber"
	"github.com/dedis/kyber/util/random"
)

type scalar struct {
	x *big.Int
}

func newScalar() kyber.Scalar {
	s := &scalar{x: &big.Int{}}
	return s.Zero()
}

func (s *scalar) Equal(a kyber.Scalar) bool {
	sm, err := s.MarshalBinary()
	if err != nil {
		return false
	}
	am, err := a.MarshalBinary()
	if err != nil {
		return false
	}
	return subtle.ConstantTimeCompare(sm, am) == 1
}

func (s *scalar) Set(a kyber.Scalar) kyber.Scalar {
	buf, _ := a.(*scalar).MarshalBinary()
	s.UnmarshalBinary(buf)
	return s
}

func (s *scalar) Clone() kyber.Scalar {
	a := newScalar()
	a.Set(s)
	return a
}

func (s *scalar) SetInt64(v int64) kyber.Scalar {
	s.x.SetInt64(v)
	return s
}

func (s *scalar) Zero() kyber.Scalar {
	return s.SetInt64(0)
}

func (s *scalar) Add(a, b kyber.Scalar) kyber.Scalar {
	ax := a.(*scalar).x
	bx := b.(*scalar).x
	s.x.Add(ax, bx)
	s.x.Mod(s.x, Order)
	return s
}

func (s *scalar) Sub(a, b kyber.Scalar) kyber.Scalar {
	ax := a.(*scalar).x
	bx := b.(*scalar).x
	s.x.Sub(ax, bx)
	s.x.Mod(s.x, Order)
	return s
}

func (s *scalar) Neg(a kyber.Scalar) kyber.Scalar {
	ax := a.(*scalar).x
	s.x.Neg(ax)
	s.x.Mod(s.x, Order)
	return s
}

func (s *scalar) One() kyber.Scalar {
	return s.SetInt64(1)
}

func (s *scalar) Mul(a, b kyber.Scalar) kyber.Scalar {
	ax := a.(*scalar).x
	bx := b.(*scalar).x
	s.x.Mul(ax, bx)
	s.x.Mod(s.x, Order)
	return s
}

func (s *scalar) Div(a, b kyber.Scalar) kyber.Scalar {
	ax := a.(*scalar).x
	bx := b.(*scalar).x
	s.x.Div(ax, bx)
	s.x.Mod(s.x, Order)
	return s
}

func (s *scalar) Inv(a kyber.Scalar) kyber.Scalar {
	ax := a.(*scalar).x
	s.x.ModInverse(ax, Order)
	return s
}

func (s *scalar) Pick(rand cipher.Stream) kyber.Scalar {
	buf := make([]byte, s.MarshalSize())
	random.Bytes(buf, rand)
	s.SetBytes(buf)
	return s
}

func (s *scalar) SetBytes(buf []byte) kyber.Scalar {
	s.UnmarshalBinary(buf)
	return s
}

func (s *scalar) Bytes() []byte {
	sm, _ := s.MarshalBinary()
	return sm
}

func (s *scalar) SetVarTime(varTime bool) error {
	panic("bn256.Scalar: unsupported operation")
}

func (s *scalar) MarshalBinary() ([]byte, error) {
	n := s.MarshalSize()
	buf := make([]byte, n)
	bytes := s.x.Bytes()
	if n < len(bytes) {
		return nil, errors.New("bn256.Scalar: unexpected size")
	}
	m := n - len(bytes)
	copy(buf[m:n], bytes)
	return buf, nil
}

func (s *scalar) MarshalTo(w io.Writer) (int, error) {
	buf, _ := s.MarshalBinary()
	return w.Write(buf)
}

func (s *scalar) UnmarshalBinary(buf []byte) error {
	n := s.MarshalSize()
	s.x.SetBytes(buf[:n])
	s.x.Mod(s.x, Order)
	return nil
}

func (s *scalar) UnmarshalFrom(r io.Reader) (int, error) {
	buf := make([]byte, s.MarshalSize())
	n, err := io.ReadFull(r, buf)
	if err != nil {
		return n, err
	}
	return n, s.UnmarshalBinary(buf)
}

func (s *scalar) MarshalSize() int {
	return len(Order.Bytes())
}

func (s *scalar) String() string {
	return "bn256.Scalar(" + s.x.String() + ")"
}
