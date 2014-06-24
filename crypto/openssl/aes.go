package openssl

// #include <openssl/aes.h>
// #cgo CFLAGS: -Wno-deprecated
// #cgo LDFLAGS: -lcrypto -ldl
import "C"

import (
	"unsafe"
)

const blocksize = 16

type aes struct {
	key *_Ctype_AES_KEY		// expanded AES key
	ctr, out [blocksize]byte	// input counter and output buffer
	idx int				// bytes of current block already used
}

func newAesCtr(key []byte) *aes {
	a := new(aes)
	a.key = &_Ctype_AES_KEY{}
	if C.AES_set_encrypt_key((*_Ctype_unsignedchar)(unsafe.Pointer(&key[0])), C.int(len(key)*8), a.key) != 0 {
		panic("C.AES_set_encrypt_key failed")
	}
	// counter automatically starts at 0
	a.idx = blocksize		// need a fresh block first time
	return a
}

func (a *aes) XORKeyStream(dst, src []byte) {
	for i := range(src) {
		if a.idx == blocksize {
			// generate a block by encrypting the current counter
			C.AES_encrypt((*_Ctype_unsignedchar)(unsafe.Pointer(&a.ctr[0])), (*_Ctype_unsignedchar)(unsafe.Pointer(&a.out[0])), a.key)

			// increment the counter
			for j := blocksize-1; ; j-- {
				a.ctr[j]++
				if a.ctr[j] != 0 {
					break
				}
			}

			a.idx = 0
		}

		dst[i] = src[i] ^ a.out[a.idx]
		a.idx++
	}
}


