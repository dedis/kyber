package bn256

import (
	"crypto/cipher"
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

// Equal ...
func (s *scalar) Equal(a kyber.Scalar) bool {
	return s.x.Cmp(a.(*scalar).x) == 0
}

// Set ...
func (s *scalar) Set(a kyber.Scalar) kyber.Scalar {
	buf, _ := a.(*scalar).MarshalBinary()
	s.UnmarshalBinary(buf)
	return s
}

// Clone ...
func (s *scalar) Clone() kyber.Scalar {
	a := NewScalar()
	a.Set(s)
	return a
}

// SetInt64 ...
func (s *scalar) SetInt64(v int64) kyber.Scalar {
	s.x.SetInt64(v)
	return s
}

// Zero ...
func (s *scalar) Zero() kyber.Scalar {
	return s.SetInt64(0)
}

// Add ...
func (s *scalar) Add(a, b kyber.Scalar) kyber.Scalar {
	ax := a.(*scalar).x
	bx := b.(*scalar).x
	s.x.Add(ax, bx)
	s.x.Mod(s.x, Order)
	return s
}

// Sub ...
func (s *scalar) Sub(a, b kyber.Scalar) kyber.Scalar {
	ax := a.(*scalar).x
	bx := b.(*scalar).x
	s.x.Sub(ax, bx)
	s.x.Mod(s.x, Order)
	return s
}

// Neg ...
func (s *scalar) Neg(a kyber.Scalar) kyber.Scalar {
	ax := a.(*scalar).x
	s.x.Neg(ax)
	s.x.Mod(s.x, Order)
	return s
}

// One ...
func (s *scalar) One() kyber.Scalar {
	return s.SetInt64(1)
}

// Mul ...
func (s *scalar) Mul(a, b kyber.Scalar) kyber.Scalar {
	ax := a.(*scalar).x
	bx := b.(*scalar).x
	s.x.Mul(ax, bx)
	s.x.Mod(s.x, Order)
	return s
}

// Div ...
func (s *scalar) Div(a, b kyber.Scalar) kyber.Scalar {
	ax := a.(*scalar).x
	bx := b.(*scalar).x
	s.x.Div(ax, bx)
	s.x.Mod(s.x, Order)
	return s
}

// Inv ...
func (s *scalar) Inv(a kyber.Scalar) kyber.Scalar {
	ax := a.(*scalar).x
	s.x.ModInverse(ax, Order)
	return s
}

// Pick ...
func (s *scalar) Pick(rand cipher.Stream) kyber.Scalar {
	buf := make([]byte, s.MarshalSize())
	random.Bytes(buf, rand)
	s.SetBytes(buf)
	return s
}

// SetBytes ...
func (s *scalar) SetBytes(buf []byte) kyber.Scalar {
	s.UnmarshalBinary(buf)
	return s
}

// Bytes ...
func (s *scalar) Bytes() []byte {
	return s.x.Bytes()
}

// SetVarTime ...
func (s *scalar) SetVarTime(varTime bool) error {
	return errors.New("bn256: no constant-time implementation available")
}

// MarshalBinary ...
func (s *scalar) MarshalBinary() ([]byte, error) {
	n := s.MarshalSize()
	buf := s.x.Bytes()
	return buf[:n], nil
}

// MarshalTo ...
func (s *scalar) MarshalTo(w io.Writer) (int, error) {
	buf, _ := s.MarshalBinary()
	return w.Write(buf)
}

// UnmarshalBinary ...
func (s *scalar) UnmarshalBinary(buf []byte) error {
	n := s.MarshalSize()
	s.x.SetBytes(buf[:n])
	return nil
}

// UnmarshalFrom ...
func (s *scalar) UnmarshalFrom(r io.Reader) (int, error) {
	buf := make([]byte, s.MarshalSize())
	n, err := io.ReadFull(r, buf)
	if err != nil {
		return n, err
	}
	return n, s.UnmarshalBinary(buf)
}

// MarshalSize ...
func (s *scalar) MarshalSize() int {
	return len(Order.Bytes())
}

// String ...
func (s *scalar) String() string {
	return "bn256.Scalar(" + s.x.String() + ")"
}
