package cipher

import (
	"log"
	"hash"
	"crypto/cipher"
	"crypto/hmac"
	"github.com/dedis/crypto/abstract"
	"github.com/dedis/crypto/ints"
)

type blockCipher struct {

	// Configuration state
	newCipher func(key []byte) (cipher.Block, error)
	newHash func() hash.Hash
	blockLen, keyLen, hashLen int
	iv []byte	// initialization vector for counter mode
	dir abstract.Direction	// cipher direction

	// Per-message cipher state
	k []byte	// master secret state from last message, 0 if unkeyed
	h hash.Hash	// hash or hmac for absorbing input
	s cipher.Stream	// stream cipher for encrypting, nil if none
}

const bufLen = 1024

var zeroBytes = make([]byte, bufLen)

// Construct a general message Cipher
// from a block cipher and a cryptographic hash function.
func NewBlockCipher(newCipher func(key []byte) (cipher.Block, error),
			newHash func() hash.Hash,
			blockLen, keyLen, hashLen int) abstract.Cipher {
	bc := blockCipher{}
	bc.newCipher = newCipher
	bc.newHash = newHash
	bc.blockLen = blockLen
	bc.keyLen = keyLen
	bc.hashLen = hashLen

	bc.h = bc.newHash()
	return &bc
}

func (bc *blockCipher) Crypt(dst, src []byte,
				options ...interface{}) abstract.Cipher {
	var more bool
	for _, opt := range(options) {
		switch v := opt.(type) {
		case abstract.More: more = true
		case abstract.Direction: bc.dir = v
		default: log.Panicf("Unsupported option %v", opt)
		}
	}

	for len(dst) > 0 {
		if len(src) == 0 {
			src = zeroBytes
		}
		l := ints.Min(len(dst), len(src))

		if bc.s == nil {
			if bc.k == nil {
				bc.k = make([]byte, bc.hashLen)
				bc.iv = make([]byte, bc.blockLen)
			}
			b, err := bc.newCipher(bc.k[:bc.keyLen])
			if err != nil {
				panic(err.Error())
			}
			bc.s = cipher.NewCTR(b, bc.iv)
		}

		if bc.dir >= 0 {
			bc.s.XORKeyStream(dst[:l], src[:l])
			bc.h.Write(dst[:l])	// encrypt-then-MAC
		} else {
			bc.h.Write(src[:l])	// MAC-then-decrypt
			bc.s.XORKeyStream(dst[:l], src[:l])
		}

		src = src[l:]
		dst = dst[l:]
	}
	if len(src) > 0 {
		bc.h.Write(src)	// absorb extra src bytes
	}
	if !more {
		bc.k = bc.h.Sum(bc.k[:0]) // update state with absorbed data
		bc.h = hmac.New(bc.newHash, bc.k)	// ready for next msg
		bc.s = nil
	}

	return bc
}

func (bc *blockCipher) KeySize() int {
	return bc.keyLen
}

func (bc *blockCipher) HashSize() int {
	return bc.hashLen
}

func (bc *blockCipher) BlockSize() int {
	return 1	// incremental encrypt/decrypt work at any granularity
}

func (bc *blockCipher) Clone(src []byte) abstract.Cipher {
	if bc.s != nil {
		panic("cannot clone cipher state mid-message")
	}

	nbc := *bc
	if bc.k != nil {	// keyed state
		nbc.k = make([]byte, bc.hashLen)
		copy(nbc.k, bc.k)
		nbc.h = hmac.New(nbc.newHash, nbc.k)
	} else {		// unkeyed state
		nbc.h = nbc.newHash()
	}

	if src != nil {
		nbc.Crypt(nil, src)
	}

	return &nbc
}

