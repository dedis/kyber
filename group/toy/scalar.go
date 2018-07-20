package toy

import (
	"crypto/cipher"
	"fmt"
	"io"
	"math/big"

	"github.com/dedis/kyber"
)

type scalar uint

func (s *scalar) Equal(s2 kyber.Scalar) bool {
	return *s == *s2.(*scalar)
}

func (s *scalar) Set(a kyber.Scalar) kyber.Scalar {
	*s = *a.(*scalar)
	return s
}

func (s *scalar) Clone() kyber.Scalar {
	v := *s
	return &v
}

func (s *scalar) SetInt64(v int64) kyber.Scalar {
	*s = scalar(v%int64(GroupOrder)+int64(GroupOrder)) % GroupOrder
	return s
}

func (s *scalar) Zero() kyber.Scalar {
	*s = 0
	return s
}

func (s *scalar) Add(a, b kyber.Scalar) kyber.Scalar {
	*s = (*a.(*scalar) + *b.(*scalar)) % GroupOrder
	return s
}

func (s *scalar) Sub(a, b kyber.Scalar) kyber.Scalar {
	*s = (*a.(*scalar) + GroupOrder - *b.(*scalar)) % GroupOrder
	return s
}

func (s *scalar) Neg(a kyber.Scalar) kyber.Scalar {
	*s = (GroupOrder - *a.(*scalar)) % GroupOrder
	return s
}

func (s *scalar) One() kyber.Scalar {
	*s = 1
	return s
}

func (s *scalar) Mul(a, b kyber.Scalar) kyber.Scalar {
	*s = (*a.(*scalar) * *b.(*scalar)) % GroupOrder
	return s
}

func (s *scalar) Div(a, b kyber.Scalar) kyber.Scalar {
	s.Inv(b)
	s.Mul(a, s)
	return s
}

func (s *scalar) Inv(a kyber.Scalar) kyber.Scalar {
	av := *a.(*scalar)
	if av == 0 {
		*s = 0
	} else {
		*s = 1
		for i := scalar(0); i < GroupOrder-2; i++ {
			*s = *s * av % GroupOrder
		}
	}
	return s
}

func (s *scalar) Pick(rand cipher.Stream) kyber.Scalar {
	var b [1]byte
	rand.XORKeyStream(b[:], b[:])
	*s = scalar(b[0]) % GroupOrder
	return s
}

func (s *scalar) SetBytes(b []byte) kyber.Scalar {
	t := big.NewInt(0).SetBytes(b)
	*s = scalar(t.Mod(t, big.NewInt(int64(GroupOrder))).Uint64())
	return nil
}

func (s *scalar) String() string {
	return fmt.Sprint(*s)
}

func (s *scalar) MarshalSize() int {
	return 1
}

func (s *scalar) MarshalTo(w io.Writer) (int, error) {
	b, err := s.MarshalBinary()
	if err != nil {
		return 0, err
	}
	return w.Write(b)
}

func (s *scalar) UnmarshalFrom(r io.Reader) (int, error) {
	var b [1]byte
	n := 0

	for {
		m, err := r.Read(b[:])
		n += m
		if m > 0 {
			err2 := s.UnmarshalBinary(b[:])
			if err2 == nil {
				return n, err
			}
		}
		if err != nil {
			return n, err
		}
	}
}

func (s *scalar) MarshalBinary() (data []byte, err error) {
	b := [1]byte{byte(*s)}
	return b[:], nil
}

func (s *scalar) UnmarshalBinary(data []byte) error {
	*s = scalar(data[0]) % GroupOrder
	return nil
}
