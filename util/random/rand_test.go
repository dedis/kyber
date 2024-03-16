package random

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"math/big"
	"strconv"
	"strings"
	"testing"
)

const size = 32
const readerStream = "some io.Reader stream to be used for testing"

func TestMixedEntropy(t *testing.T) {
	r := strings.NewReader(readerStream)
	cipher := New(r, rand.Reader)

	src := make([]byte, size)
	copy(src, []byte("source buffer"))
	dst := make([]byte, size+1)
	dst[len(dst)-1] = 0xff

	cipher.XORKeyStream(dst[:len(dst)-1], src)
	if len(src) > 0 && bytes.Equal(src, dst[0:len(src)]) {
		t.Fatal("src and dst should not be equal")
	}
	if dst[len(dst)-1] != 0xff {
		t.Fatal("last byte of dst chagned")
	}
}

func TestEmptyReader(t *testing.T) {
	//expecting a panic
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("code did not panicked but should have")
		}
	}()

	r := strings.NewReader("too small io.Reader")
	cipher := New(r)
	src := make([]byte, size)
	copy(src, []byte("hello"))
	dst := make([]byte, size)
	cipher.XORKeyStream(dst, src)
}

func TestCryptoOnly(t *testing.T) {
	cipher := New()
	src := make([]byte, size)
	copy(src, []byte("hello"))
	dst1 := make([]byte, size)
	cipher.XORKeyStream(dst1, src)
	dst2 := make([]byte, size)
	cipher.XORKeyStream(dst2, src)
	if bytes.Equal(dst1, dst2) {
		t.Fatal("dst1 and dst2 should not be equal")
	}
}

func TestUserOnly(t *testing.T) {
	cipher1 := New(strings.NewReader(readerStream))
	src := make([]byte, size)
	copy(src, []byte("hello"))
	dst1 := make([]byte, size)
	cipher1.XORKeyStream(dst1, src)
	cipher2 := New(strings.NewReader(readerStream))
	dst2 := make([]byte, size)
	cipher2.XORKeyStream(dst2, src)
	if !bytes.Equal(dst1, dst2) {
		t.Fatal("dst1/dst2 should be equal")
	}
}

func TestIncorrectSize(t *testing.T) {
	//expecting a panic
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("code did not panicked but should have")
		}
	}()
	cipher := New(rand.Reader)
	src := make([]byte, size)
	copy(src, []byte("hello"))
	dst := make([]byte, size+1)
	cipher.XORKeyStream(dst, src)
}

func TestBits(t *testing.T) {
	testCases := []struct {
		bitlen uint // input bit length
		exact  bool // whether the exact bit length should be enforced
	}{
		{bitlen: 128, exact: false},
		{bitlen: 256, exact: true},
		{bitlen: 512, exact: false},
		{bitlen: 1024, exact: true},
	}

	for _, tc := range testCases {
		t.Run(fmt.Sprintf("bitlen: %d exact: %s", tc.bitlen, strconv.FormatBool(tc.exact)), func(t *testing.T) {
			r := strings.NewReader(readerStream)
			cipher := New(r, rand.Reader)

			bigIntBytes := Bits(tc.bitlen, tc.exact, cipher)
			bigInt := new(big.Int).SetBytes(bigIntBytes)

			// Check if the bit length matches the expected length
			expectedBitLen := tc.bitlen
			if tc.exact && uint(bigInt.BitLen()) != expectedBitLen {
				t.Errorf("Generated BigInt with exact bits doesn't match the expected bit length: got %d, expected %d", bigInt.BitLen(), expectedBitLen)
			} else if !tc.exact && uint(bigInt.BitLen()) > expectedBitLen {
				t.Errorf("Generated BigInt with more bits than maximum bit length: got %d, expected at most %d", bigInt.BitLen(), expectedBitLen)
			}
		})
	}
}

func TestInt(t *testing.T) {
	testCases := []struct {
		modulusBitLen uint // Bit length of the modulus
	}{
		{128},
		{256},
		{512},
		{1024},
	}

	for _, tc := range testCases {
		t.Run(fmt.Sprintf("modulusBitlen: %d", tc.modulusBitLen), func(t *testing.T) {
			modulus, err := rand.Prime(rand.Reader, int(tc.modulusBitLen))
			if err != nil {
				t.Fatalf("Failed to generate random prime: %v", err)
			}

			r := strings.NewReader(readerStream)
			cipher := New(r, rand.Reader)

			randomInt := Int(modulus, cipher)

			// Check if the generated BigInt is less than the modulus
			if randomInt.Cmp(modulus) >= 0 {
				t.Errorf("Generated BigInt %v is not less than the modulus %v", randomInt, modulus)
			}
		})
	}
}
