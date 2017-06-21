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

func do_carry_uncentered(limbs [24]int64, i int) {
	carry := limbs[i] >> 21
	limbs[i+1] += carry
	limbs[i] -= carry << 21
}

// Carry excess from the `i`-th limb into the `(i+1)`-th limb.
// Postcondition: `-2^20 <= limbs[i] < 2^20`.
func do_carry_centered(limbs [24]int64, i int) {
	carry := (limbs[i] + (1 << 20)) >> 21
	limbs[i+1] += carry
	limbs[i] -= carry << 21
}

func do_reduction(limbs [24]int64, i int) {
	limbs[i-12] += limbs[i] * 666643
	limbs[i-11] += limbs[i] * 470296
	limbs[i-10] += limbs[i] * 654183
	limbs[i-9] -= limbs[i] * 997805
	limbs[i-8] += limbs[i] * 136657
	limbs[i-7] -= limbs[i] * 683901
	limbs[i] = 0
}

func scReduce(s [24]int64) {
	limbs := s
	//for i in 0..23 {
	for i := 0; i < 23; i++ {
		do_carry_centered(limbs, i)
	}
	//for i in (0..23).filter(|x| x % 2 == 1) {
	for i := 1; i < 23; i += 2 {
		do_carry_centered(limbs, i)
	}

	do_reduction(limbs, 23)
	do_reduction(limbs, 22)
	do_reduction(limbs, 21)
	do_reduction(limbs, 20)
	do_reduction(limbs, 19)
	do_reduction(limbs, 18)

	//for i in (6..18).filter(|x| x % 2 == 0) {
	for i := 6; i < 18; i += 2 {
		do_carry_centered(limbs, i)
	}

	//  for i in (6..16).filter(|x| x % 2 == 1) {
	for i := 7; i < 16; i += 2 {
		do_carry_centered(limbs, i)
	}
	do_reduction(limbs, 17)
	do_reduction(limbs, 16)
	do_reduction(limbs, 15)
	do_reduction(limbs, 14)
	do_reduction(limbs, 13)
	do_reduction(limbs, 12)

	//for i in (0..12).filter(|x| x % 2 == 0) {
	for i := 0; i < 12; i += 2 {
		do_carry_centered(limbs, i)
	}
	//for i in (0..12).filter(|x| x % 2 == 1) {
	for i := 1; i < 12; i += 2 {
		do_carry_centered(limbs, i)
	}

	do_reduction(limbs, 12)

	//for i in 0..12 {
	for i := 0; i < 12; i++ {
		do_carry_uncentered(limbs, i)
	}

	do_reduction(limbs, 12)

	//for i in 0..11 {
	for i := 0; i < 11; i++ {
		do_carry_uncentered(limbs, i)
	}
}
