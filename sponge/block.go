package sponge

import (
	//"crypto/cipher"
)

/*
type genSponge struct {
	newstrm func([]byte)cipher.Stream
	keylen int
	s cipher.Stream
	h hash.Hash
}

// Construct a Sponge cipher generically
// from a block cipher and a cryptographic hash function.
func BlockSponge(newStream func([]byte)cipher.Stream, key []byte,
			hash hash.Hash) Sponge {
	s := genSponge{newStream,len(key),newStream(key),hash}
	return Sponge(&s)
}


// End the current message,
// updating the sponge's stream cipher based on the absorbed input.
func (bs *genSponge) end() {
	sum := bs.h.Sum(nil)[:bs.keylen]
	bs.s.XORKeyStream(sum,sum)
	bs.s = bs.newstrm(sum)
	bs.h.Reset()
}

func (bs *genSponge) Encrypt(dst,src []byte, more bool) {
	if dst != nil {		// squeezing and maybe absorbing
		if src == nil {
			src = make([]byte,len(dst))
		} else if len(src) != len(dst) {
			panic("mismatched lengths")
		}
		bs.s.XORKeyStream(dst,src)
		bs.h.Write(dst)		// absorb ciphertext
	} else {
		bs.h.Write(src)		// absorb plaintext
	}
	if !more {
		bs.end()
	}
}

func (bs *genSponge) Decrypt(dst,src []byte, more bool) {
	if len(src) != len(dst) {
		panic("mismatched lengths")
	}
	bs.h.Write(src)			// absorb ciphertext
	bs.s.XORKeyStream(dst,src)	// decrypt ciphertext
	if !more {
		bs.end()
	}
}

func (bs *genSponge) Clone() SpongeCipher {
	XXX	this is the problem - might need to expose block cipher
}

func (bs *genSponge) BlockSize() int {
	return bs.h.BlockSize()
}

func (bs *genSponge) KeyLen() int {
}

*/
