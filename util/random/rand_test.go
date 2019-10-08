package random

import (
	"bytes"
	"crypto/rand"
	"strings"
	"testing"
)

const size = 32

func TestMixedEntropy(t *testing.T) {
	r := strings.NewReader("some io.Reader stream to be used for testing")
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
	seed := "some io.Reader stream to be used for testing"
	cipher1 := New(strings.NewReader(seed))
	src := make([]byte, size)
	copy(src, []byte("hello"))
	dst1 := make([]byte, size)
	cipher1.XORKeyStream(dst1, src)
	cipher2 := New(strings.NewReader(seed))
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
	cipher := New()
	src := make([]byte, size)
	copy(src, []byte("hello"))
	dst := make([]byte, size+1)
	cipher.XORKeyStream(dst, src)
}
