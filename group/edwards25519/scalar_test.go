package edwards25519

import (
	"testing"

	"github.com/dedis/kyber/random"

	kyber "gopkg.in/dedis/kyber.v1"
)

type SimpleCTScalar struct {
	*scalar
}

func newSimpleCTScalar() kyber.Scalar {
	return &SimpleCTScalar{&scalar{}}
}

var one = new(scalar).SetInt64(1).(*scalar)
var zero = new(scalar).Zero().(*scalar)

var minusOne = new(scalar).SetBytes([]byte{0xec, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10}).(*scalar)

func (s *SimpleCTScalar) Add(s1, s2 kyber.Scalar) kyber.Scalar {
	sc1 := s1.(*SimpleCTScalar)
	sc2 := s2.(*SimpleCTScalar)

	// a * b + c = a * 1 + c
	scMulAdd(&s.v, &sc1.v, &one.v, &sc2.v)
	return s
}

func (s *SimpleCTScalar) Mul(s1, s2 kyber.Scalar) kyber.Scalar {
	sc1 := s1.(*SimpleCTScalar)
	sc2 := s2.(*SimpleCTScalar)

	// a * b + c = a * b + 0
	scMulAdd(&s.v, &sc1.v, &sc2.v, &zero.v)
	return s
}

func (s *SimpleCTScalar) Sub(s1, s2 kyber.Scalar) kyber.Scalar {
	sc1 := s1.(*SimpleCTScalar)
	sc2 := s2.(*SimpleCTScalar)

	// a * b + c = -1 * a + c
	scMulAdd(&s.v, &minusOne.v, &sc1.v, &sc2.v)
	return s

}

func (s *SimpleCTScalar) Equal(s2 kyber.Scalar) bool {
	return s.scalar.Equal(s2.(*SimpleCTScalar).scalar)
}

func TestSimpleCTScalar(t *testing.T) {
	s1 := newSimpleCTScalar()
	s2 := newSimpleCTScalar()
	s3 := newSimpleCTScalar()

	s1.SetInt64(2)
	s2.Pick(random.Stream)

	s22 := newSimpleCTScalar().Add(s2, s2)

	if !s3.Mul(s1, s2).Equal(s22) {
		t.Fail()
	}
}

func BenchmarkCTScalarSimpleAdd(b *testing.B) {
	var seed = testSuite.Cipher([]byte("hello world"))
	s1 := newSimpleCTScalar()
	s2 := newSimpleCTScalar()
	s3 := newSimpleCTScalar()
	s1.Pick(seed)
	s2.Pick(seed)

	for i := 0; i < b.N; i++ {
		s3.Add(s1, s2)
	}
}

func BenchmarkCTScalarAdd(b *testing.B) {
	var seed = testSuite.Cipher([]byte("hello world"))
	s1 := testSuite.Scalar()
	s2 := testSuite.Scalar()
	s3 := testSuite.Scalar()
	s1.Pick(seed)
	s2.Pick(seed)

	for i := 0; i < b.N; i++ {
		s3.Add(s1, s2)
	}
}

func BenchmarkCTScalarSimpleMul(b *testing.B) {
	var seed = testSuite.Cipher([]byte("hello world"))
	s1 := newSimpleCTScalar()
	s2 := newSimpleCTScalar()
	s3 := newSimpleCTScalar()
	s1.Pick(seed)
	s2.Pick(seed)

	for i := 0; i < b.N; i++ {
		s3.Mul(s1, s2)
	}
}

func BenchmarkCTScalarMul(b *testing.B) {
	var seed = testSuite.Cipher([]byte("hello world"))
	s1 := testSuite.Scalar()
	s2 := testSuite.Scalar()
	s3 := testSuite.Scalar()
	s1.Pick(seed)
	s2.Pick(seed)

	for i := 0; i < b.N; i++ {
		s3.Mul(s1, s2)
	}
}

func BenchmarkCTScalarSimpleSub(b *testing.B) {
	var seed = testSuite.Cipher([]byte("hello world"))
	s1 := newSimpleCTScalar()
	s2 := newSimpleCTScalar()
	s3 := newSimpleCTScalar()
	s1.Pick(seed)
	s2.Pick(seed)

	for i := 0; i < b.N; i++ {
		s3.Sub(s1, s2)
	}
}

func BenchmarkCTScalarSub(b *testing.B) {
	var seed = testSuite.Cipher([]byte("hello world"))
	s1 := testSuite.Scalar()
	s2 := testSuite.Scalar()
	s3 := testSuite.Scalar()
	s1.Pick(seed)
	s2.Pick(seed)

	for i := 0; i < b.N; i++ {
		s3.Sub(s1, s2)
	}
}
