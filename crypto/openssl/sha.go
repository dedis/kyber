package openssl

// #include <openssl/sha.h>
// #cgo CFLAGS: -Wno-deprecated
// #cgo LDFLAGS: -lcrypto
import "C"

import (
	"unsafe"
)


// SHA256 hash function
type sha256 struct {
	ctx *_Ctype_SHA256_CTX
}

func (h *sha256) Reset() {
	h.ctx = &_Ctype_SHA256_CTX{}
	if C.SHA256_Init(h.ctx) != 1 {
		panic("SHA256_Init failed")	// hash funcs shouldn't fail
	}
}

func (h *sha256) Write(p []byte) (n int, err error) {
	l := len(p)
	if C.SHA256_Update(h.ctx, unsafe.Pointer(&p[0]), C.size_t(l)) == 0 {
		panic("SHA256_Update failed")
	}
	return l,nil
}

func (h *sha256) Size() int {
	return C.SHA256_DIGEST_LENGTH
}

func (h *sha256) BlockSize() int {
	return C.SHA256_CBLOCK
}

func (h *sha256) Sum(b []byte) []byte {
	c := *h.ctx
	d := make([]byte, C.SHA256_DIGEST_LENGTH)
	if C.SHA256_Final((*_Ctype_unsignedchar)(unsafe.Pointer(&d[0])),
			&c) == 0 {
		panic("SHA256_Final failed")
	}
	return append(b, d...)
}

func newSha256() *sha256 {
	s := new(sha256)
	s.Reset()
	return s
}


