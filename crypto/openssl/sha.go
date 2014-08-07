package openssl

// #include <openssl/sha.h>
// #cgo CFLAGS: -Wno-deprecated
// #cgo LDFLAGS: -lcrypto
import "C"

import (
	"unsafe"
)


// SHA224 hash function
type sha224 struct {
	ctx *_Ctype_struct_SHA256state_st
}

func (h *sha224) Reset() {
	h.ctx = &_Ctype_struct_SHA256state_st{}
	if C.SHA224_Init(h.ctx) != 1 {
		panic("SHA224_Init failed")	// hash funcs shouldn't fail
	}
}

func (h *sha224) Write(p []byte) (n int, err error) {
	l := len(p)
	if C.SHA224_Update(h.ctx, unsafe.Pointer(&p[0]), C.size_t(l)) == 0 {
		panic("SHA224_Update failed")
	}
	return l,nil
}

func (h *sha224) Size() int {
	return C.SHA224_DIGEST_LENGTH
}

func (h *sha224) BlockSize() int {
	return C.SHA256_CBLOCK
}

func (h *sha224) Sum(b []byte) []byte {
	c := *h.ctx
	d := make([]byte, C.SHA224_DIGEST_LENGTH)
	if C.SHA224_Final((*_Ctype_unsignedchar)(unsafe.Pointer(&d[0])),
			&c) == 0 {
		panic("SHA224_Final failed")
	}
	return append(b, d...)
}

func newSha224() *sha224 {
	s := new(sha224)
	s.Reset()
	return s
}


// SHA256 hash function
type sha256 struct {
	ctx *_Ctype_struct_SHA256state_st
}

func (h *sha256) Reset() {
	h.ctx = &_Ctype_struct_SHA256state_st{}
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


// SHA384 hash function
type sha384 struct {
	ctx *_Ctype_struct_SHA512state_st
}

func (h *sha384) Reset() {
	h.ctx = &_Ctype_struct_SHA512state_st{}
	if C.SHA384_Init(h.ctx) != 1 {
		panic("SHA384_Init failed")	// hash funcs shouldn't fail
	}
}

func (h *sha384) Write(p []byte) (n int, err error) {
	l := len(p)
	if C.SHA384_Update(h.ctx, unsafe.Pointer(&p[0]), C.size_t(l)) == 0 {
		panic("SHA384_Update failed")
	}
	return l,nil
}

func (h *sha384) Size() int {
	return C.SHA384_DIGEST_LENGTH
}

func (h *sha384) BlockSize() int {
	return C.SHA512_CBLOCK
}

func (h *sha384) Sum(b []byte) []byte {
	c := *h.ctx
	d := make([]byte, C.SHA384_DIGEST_LENGTH)
	if C.SHA384_Final((*_Ctype_unsignedchar)(unsafe.Pointer(&d[0])),
			&c) == 0 {
		panic("SHA384_Final failed")
	}
	return append(b, d...)
}

func newSha384() *sha384 {
	s := new(sha384)
	s.Reset()
	return s
}


// SHA512 hash function
type sha512 struct {
	ctx *_Ctype_struct_SHA512state_st
}

func (h *sha512) Reset() {
	h.ctx = &_Ctype_struct_SHA512state_st{}
	if C.SHA512_Init(h.ctx) != 1 {
		panic("SHA512_Init failed")	// hash funcs shouldn't fail
	}
}

func (h *sha512) Write(p []byte) (n int, err error) {
	l := len(p)
	if C.SHA512_Update(h.ctx, unsafe.Pointer(&p[0]), C.size_t(l)) == 0 {
		panic("SHA512_Update failed")
	}
	return l,nil
}

func (h *sha512) Size() int {
	return C.SHA512_DIGEST_LENGTH
}

func (h *sha512) BlockSize() int {
	return C.SHA512_CBLOCK
}

func (h *sha512) Sum(b []byte) []byte {
	c := *h.ctx
	d := make([]byte, C.SHA512_DIGEST_LENGTH)
	if C.SHA512_Final((*_Ctype_unsignedchar)(unsafe.Pointer(&d[0])),
			&c) == 0 {
		panic("SHA512_Final failed")
	}
	return append(b, d...)
}

func newSha512() *sha512 {
	s := new(sha512)
	s.Reset()
	return s
}


