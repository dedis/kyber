package xof

import (
	"bytes"
	"math"
	"testing"

	"github.com/dedis/kyber"
	"github.com/dedis/kyber/xof/blake"
	"github.com/dedis/kyber/xof/keccak"
	"github.com/stretchr/testify/require"
)

type factory interface {
	XOF(seed []byte) kyber.XOF
}
type blakeF struct{}

func (b *blakeF) XOF(seed []byte) kyber.XOF { return blake.New(seed) }

type keccakF struct{}

func (b *keccakF) XOF(seed []byte) kyber.XOF { return keccak.New(seed) }

var impls = []factory{&blakeF{}, &keccakF{}}

func TestEncDec(t *testing.T) {
	lengths := []int{0, 1, 16, 1024, 8192}

	for _, i := range impls {
		for _, j := range lengths {
			testEncDec(t, i, j)
		}
	}
}

func testEncDec(t *testing.T, s factory, size int) {
	t.Logf("implementation %T sz %v", s, size)
	key := []byte("key")

	s1 := s.XOF(key)
	s2 := s.XOF(key)

	src := make([]byte, size)
	copy(src, []byte("hello"))

	dst := make([]byte, len(src)+1)
	dst[len(dst)-1] = 0xff

	s1.XORKeyStream(dst, src)
	if len(src) > 0 && bytes.Equal(src, dst[0:len(src)]) {
		t.Fatal("src/dst should not be equal")
	}
	if dst[len(dst)-1] != 0xff {
		t.Fatal("last byte of dst chagned")
	}

	dst2 := make([]byte, len(src))
	s2.XORKeyStream(dst2, dst[0:len(src)])
	if !bytes.Equal(src, dst2) {
		t.Fatal("src/dst2 should be equal", src, dst2)
	}
}

func TestClone(t *testing.T) {
	for _, i := range impls {
		testClone(t, i)
	}
}

func testClone(t *testing.T, s factory) {
	t.Logf("implementation %T", s)
	key := []byte("key")

	s1 := s.XOF(key)
	s2 := s1.Clone()

	src := []byte("hello")
	dst := make([]byte, len(src)+1)
	dst[len(dst)-1] = 0xff

	s1.XORKeyStream(dst, src)
	if bytes.Equal(src, dst[0:len(src)]) {
		t.Fatal("src/dst should not be equal")
	}
	if dst[len(dst)-1] != 0xff {
		t.Fatal("last byte of dst chagned")
	}

	dst2 := make([]byte, len(src))
	s2.XORKeyStream(dst2, dst[0:len(src)])
	if !bytes.Equal(src, dst2) {
		t.Fatal("src/dst2 should be equal", src, dst2)
	}
}

func TestWriteReadWrite(t *testing.T) {
	for _, i := range impls {
		testWriteReadWrite(t, i)
	}
}

func testWriteReadWrite(t *testing.T, s factory) {
	t.Logf("implementation %T", s)
	key := []byte("key")
	s1 := s.XOF(key)
	src := []byte("hello")
	dst := make([]byte, 100)
	s1.XORKeyStream(dst, src)
	require.Panics(t, func() { s1.Write(src) })
}

func TestRandom(t *testing.T) {
	for _, i := range impls {
		testRandom(t, i)
	}
}

func testRandom(t *testing.T, s factory) {
	t.Logf("implementation %T", s)
	xof1 := s.XOF(nil)

	for i := 0; i < 1000; i++ {
		dst1 := make([]byte, 1024)
		xof1.Read(dst1)
		dst2 := make([]byte, 1024)
		xof1.Read(dst2)
		d := bitDiff(dst1, dst2)
		if math.Abs(d-0.50) > 0.1 {
			t.Fatalf("bitDiff %v", d)
		}
	}

	// Check that two seeds give expected mean bitdiff on first block
	xof1 = s.XOF([]byte("a"))
	xof2 := s.XOF([]byte("b"))
	dst1 := make([]byte, 1024)
	xof1.Read(dst1)
	dst2 := make([]byte, 1024)
	xof2.Read(dst2)
	d := bitDiff(dst1, dst2)
	if math.Abs(d-0.50) > 0.1 {
		t.Fatalf("two seed bitDiff %v", d)
	}
}

// bitDiff compares the bits between two arrays returning the fraction
// of differences. If the two arrays are not of the same length
// no comparison is made and a -1 is returned.
func bitDiff(a, b []byte) float64 {
	if len(a) != len(b) {
		return -1
	}

	count := 0
	for i := 0; i < len(a); i++ {
		for j := 0; j < 8; j++ {
			count += int(((a[i] ^ b[i]) >> uint(j)) & 1)
		}
	}

	return float64(count) / float64(len(a)*8)
}
