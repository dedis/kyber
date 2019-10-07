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
	cipher := NewMixedStream(r, rand.Reader)

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
	cipher := NewMixedStream(r)
	src := make([]byte, size)
	copy(src, []byte("hello"))
	dst := make([]byte, size)
	cipher.XORKeyStream(dst, src)
}

func TestCryptoOnly(t *testing.T) {
	cipher := NewMixedStream()
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
	r1 := strings.NewReader("some io.Reader stream to be used for testing")
	cipher1 := NewMixedStream(r1)
	src := make([]byte, size)
	copy(src, []byte("hello"))
	dst1 := make([]byte, size)
	cipher1.XORKeyStream(dst1, src)
	r2 := strings.NewReader("some io.Reader stream to be used for testing")
	cipher2 := NewMixedStream(r2)
	dst2 := make([]byte, size)
	cipher2.XORKeyStream(dst2, src)
	if !bytes.Equal(dst1, dst2) {
		t.Fatal("dst1/dst2 should be equal")
	}
}
