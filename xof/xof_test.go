package xof

import (
	"bytes"
	"math"
	"testing"

	"github.com/dedis/kyber"
	"github.com/dedis/kyber/xof/blake2xb"
	"github.com/dedis/kyber/xof/keccak"
	"github.com/stretchr/testify/require"
)

type blakeF struct{}

func (b *blakeF) XOF(seed []byte) kyber.XOF { return blake2xb.New(seed) }

type keccakF struct{}

func (b *keccakF) XOF(seed []byte) kyber.XOF { return keccak.New(seed) }

var impls = []kyber.XOFFactory{&blakeF{}, &keccakF{}}

func TestEncDec(t *testing.T) {
	lengths := []int{0, 1, 16, 1024, 8192}

	for _, i := range impls {
		for _, j := range lengths {
			testEncDec(t, i, j)
		}
	}
}

func testEncDec(t *testing.T, s kyber.XOFFactory, size int) {
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

func testClone(t *testing.T, s kyber.XOFFactory) {
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

func TestErrors(t *testing.T) {
	for _, i := range impls {
		testErrors(t, i)
	}
}

func testErrors(t *testing.T, s kyber.XOFFactory) {
	t.Logf("implementation %T", s)

	// Write-after-read: panic
	key := []byte("key")
	s1 := s.XOF(key)
	src := []byte("hello")
	dst := make([]byte, 100)
	s1.XORKeyStream(dst, src)
	require.Panics(t, func() { s1.Write(src) })

	// Dst too short: panic
	require.Panics(t, func() { s1.XORKeyStream(dst[0:len(src)-1], src) })
}

func TestRandom(t *testing.T) {
	for _, i := range impls {
		testRandom(t, i)
	}
}

func testRandom(t *testing.T, s kyber.XOFFactory) {
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

func TestNoSeed(t *testing.T) {
	for _, i := range impls {
		testNoSeed(t, i)
	}
}

func testNoSeed(t *testing.T, s kyber.XOFFactory) {
	t.Logf("implementation %T", s)

	xof1 := s.XOF(nil)
	dst1 := make([]byte, 1024)
	xof1.Read(dst1)

	xof2 := s.XOF([]byte{})
	dst2 := make([]byte, 1024)
	xof2.Read(dst2)
	if !bytes.Equal(dst1, dst2) {
		t.Fatal("hash with two flavors of zero seed not same")
	}
}

func TestReseed(t *testing.T) {
	for _, i := range impls {
		testReseed(t, i)
	}
}

func testReseed(t *testing.T, s kyber.XOFFactory) {
	t.Logf("implementation %T", s)
	seed := []byte("seed")

	xof1 := s.XOF(seed)
	dst1 := make([]byte, 1024)
	xof1.Read(dst1)
	// Without Reseed: panic.
	require.Panics(t, func() { xof1.Write(seed) })
	// After Reseed, does not panic.
	xof1.Reseed()
	xof2 := xof1.Clone()
	require.NotPanics(t, func() { xof1.Write(seed) })

	dst2 := make([]byte, 1024)
	xof2.Read(dst2)

	d := bitDiff(dst1, dst2)
	if math.Abs(d-0.50) > 0.1 {
		t.Fatalf("reseed bitDiff %v", d)
	}
}

func TestEncDecMismatch(t *testing.T) {
	for _, i := range impls {
		testEncDecMismatch(t, i)
	}
}

func testEncDecMismatch(t *testing.T, s kyber.XOFFactory) {
	t.Logf("implementation %T", s)
	seed := []byte("seed")
	x1 := s.XOF(seed)
	x2 := s.XOF(seed)
	msg := []byte("hello world")
	enc := make([]byte, len(msg))
	dec := make([]byte, len(msg))
	x1.XORKeyStream(enc[0:3], msg[0:3])
	x1.XORKeyStream(enc[3:4], msg[3:4])
	x1.XORKeyStream(enc[4:], msg[4:])
	x2.XORKeyStream(dec[0:5], enc[0:5])
	x2.XORKeyStream(dec[5:], enc[5:])
	if !bytes.Equal(msg, dec) {
		t.Fatal("wrong decode")
	}
}
