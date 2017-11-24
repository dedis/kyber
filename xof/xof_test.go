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

func TestErrors(t *testing.T) {
	for _, i := range impls {
		testErrors(t, i)
	}
}

func testErrors(t *testing.T, s factory) {
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

func TestNoSeed(t *testing.T) {
	for _, i := range impls {
		testNoSeed(t, i)
	}
}

func testNoSeed(t *testing.T, s factory) {
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

func testReseed(t *testing.T, s factory) {
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

//
// TODO: port this test to XOF

// // AuthenticateAndEncrypt tests a Cipher if:
// // 1) Encryption / decryption works
// // 2) Encryption / decryption with different key don't work
// // 3) Changing a bit in the ciphertext or mac results in failed mac check
// // 4) Different keys produce sufficiently random output
// func AuthenticateAndEncrypt(t *testing.T,
// 	newCipher func([]byte, ...interface{}) kyber.Cipher,
// 	n int, minDiff float64, text []byte) {
// 	cryptsize := len(text)
// 	decrypted := make([]byte, len(text))

// 	bc := newCipher(nil)
// 	keysize := bc.KeySize()
// 	hashsize := bc.HashSize()
// 	mac := make([]byte, hashsize)

// 	ncrypts := make([][]byte, n)
// 	nkeys := make([][]byte, n)
// 	nmacs := make([][]byte, n)

// 	// Encrypt / decrypt / mac test
// 	for i := range nkeys {
// 		nkeys[i] = make([]byte, keysize)
// 		_, _ = rand.Read(nkeys[i])
// 		bc = newCipher(nkeys[i])
// 		ncrypts[i] = make([]byte, cryptsize)
// 		bc.Message(ncrypts[i], text, ncrypts[i])
// 		nmacs[i] = make([]byte, hashsize)
// 		bc.Message(nmacs[i], nil, nil)

// 		bc = newCipher(nkeys[i])
// 		bc.Message(decrypted, ncrypts[i], ncrypts[i])
// 		if !bytes.Equal(text, decrypted) {
// 			t.Log("Encryption / Decryption failed", i)
// 			t.FailNow()
// 		}

// 		bc.Message(mac, nmacs[i], nil)
// 		if subtle.ConstantTimeAllEq(mac, 0) != 1 {
// 			t.Log("MAC Check failed")
// 			t.FailNow()
// 		}
// 	}

// 	// Different keys test
// 	for i := range ncrypts {
// 		for j := range ncrypts {
// 			if i == j {
// 				continue
// 			}
// 			bc = newCipher(nkeys[i])
// 			bc.Message(decrypted, ncrypts[j], ncrypts[j])
// 			bc.Message(mac, nmacs[j], nil)
// 			if subtle.ConstantTimeAllEq(mac, 0) == 1 {
// 				t.Log("MAC Check passed")
// 				t.FailNow()
// 			}
// 		}
// 	}

// 	// Not enough randomness in 1 byte to pass this consistently
// 	if len(ncrypts[0]) < 8 {
// 		return
// 	}

// 	// Bit difference test
// 	for i := range ncrypts {
// 		for j := i + 1; j < len(ncrypts); j++ {
// 			diff := bitDiff(ncrypts[i], ncrypts[j])
// 			if diff < minDiff {
// 				t.Log("round", i, j, ": Encryptions not sufficiently different", diff)
// 				t.FailNow()
// 			}
// 		}
// 	}

// 	deltacopy := make([]byte, cryptsize)

// 	// Bits in either testmsg or testmac should be flipped
// 	// then the resulting MAC check should fail
// 	deltatest := func(index int, testmsg []byte, testmac []byte) {
// 		bc = newCipher(nkeys[index])
// 		bc.Message(decrypted, testmsg, testmsg)
// 		bc.Message(mac, testmac, nil)
// 		if subtle.ConstantTimeAllEq(mac, 0) == 1 {
// 			t.Log("MAC Check passed")
// 			t.FailNow()
// 		}
// 	}

// 	for i := range ncrypts {
// 		copy(ncrypts[i], deltacopy)

// 		deltacopy[0] ^= 255
// 		deltatest(i, deltacopy, nmacs[i])
// 		deltacopy[0] = ncrypts[i][0]

// 		deltacopy[len(deltacopy)/2-1] ^= 255
// 		deltatest(i, deltacopy, nmacs[i])
// 		deltacopy[len(deltacopy)/2-1] = ncrypts[i][len(deltacopy)/2-1]

// 		deltacopy[len(deltacopy)-1] ^= 255
// 		deltatest(i, deltacopy, nmacs[i])
// 		deltacopy[len(deltacopy)-1] = ncrypts[i][len(deltacopy)-1]

// 		deltamac := make([]byte, hashsize)
// 		copy(nmacs[i], deltamac)
// 		deltamac[0] ^= 255
// 		deltatest(i, ncrypts[i], deltamac)
// 	}
// }
