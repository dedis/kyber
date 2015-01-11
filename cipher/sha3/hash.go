package sha3

import (
	"hash"
	"github.com/dedis/crypto/cipher"
	"github.com/dedis/crypto/util"
	"github.com/dedis/crypto/ints"
)

type spongeHash struct {
	sponge func() cipher.Sponge
	cur cipher.Sponge
	buf []byte

	hashLen	int		// recommended hash output length

	// dsbyte contains the "domain separation" value and the first bit of
	// the padding. In sections 6.1 and 6.2 of [1], the SHA-3 and SHAKE
	// functions are defined with bits appended to the message: SHA-3
	// functions have 01 and SHAKE functions have 1111. Because of the way
	// that bits are numbered from the LSB upwards, that ends up as
	// 00000010b and 00001111b, respectively. Then the padding rule from
	// section 5.1 is applied to pad to a multiple of the rate, which
	// involves adding a 1 bit, zero or more zero bits and then a final one
	// bit. The first one bit from the padding is merged into the dsbyte
	// value giving 00000110b (0x06) and 00011111b (0x1f), respectively.
	//
	// [1] http://csrc.nist.gov/publications/drafts/fips-202/fips_202_draft.pdf,
	dsbyte  byte
}

// Create a cryptographic Hash from an arbitrary sponge function,
// configured to produce hashes of a specified length in bytes,
// using SHA3-standard padding with the given domain-separator byte.
func NewHash(sponge func() cipher.Sponge, hashLen int, dsbyte byte) hash.Hash {
	sh := spongeHash{}
	sh.sponge = sponge
	sh.cur = sponge()
	sh.buf = make([]byte,0,sh.cur.Rate())
	sh.hashLen = hashLen
	sh.dsbyte = dsbyte
	return &sh
}

func (sh *spongeHash) Init(sponge func() cipher.Sponge) *spongeHash {
	return sh
}

func (sh *spongeHash) Write(src []byte) (int,error) {
	bs := sh.cur.Rate()
	act := len(src)
	for len(src) > 0 {
		lold := len(sh.buf)
		lnew := lold+len(src)
		if lold == 0 && lnew >= bs {		// fast path
			for len(src) >= bs {
				sh.cur.Transform(nil, src[:bs], nil)
				src = src[bs:]
			}
		} else if lnew >= bs {			// filling a block
			n := bs-lold
			sh.buf = append(sh.buf,src[:n]...)
			sh.cur.Transform(nil, sh.buf, nil)
			sh.buf = sh.buf[:0]
			src = src[n:]
		} else {				// incomplete block
			sh.buf = append(sh.buf,src...)
			break
		}
	}
	return act,nil
}

func (sh *spongeHash) Sum(b []byte) []byte {

	// Clone the sponge state to leave the original one unaffected
	sp := sh.cur.Clone()
	bs := sp.Rate()

	// Pad final block with this instance's domain-separator bits.
	n := len(sh.buf)
	buf := sh.buf[:bs]
	buf[n] = sh.dsbyte
	n++

	// Fill out the remainder of the block with zeros
	for ; n < bs; n++ {
		buf[n] = 0
	}

	// This adds the final one bit for the padding. Because of the way that
	// bits are numbered from the LSB upwards, the final bit is the MSB of
	// the last byte.
	buf[n-1] ^= 0x80

	// Squeeze out a hash of any requested size.
	b,hash := util.Grow(b,sh.hashLen)
	for len(hash) > 0 {
		l := ints.Min(bs, len(hash))
		sp.Transform(hash[:l], buf, nil)
		hash = hash[l:]
		buf = nil
	}
	return b
}

func (sh *spongeHash) Reset() {
	sh.cur = sh.sponge()
	sh.buf = sh.buf[:0]
}

func (sh *spongeHash) Size() int {
	return sh.hashLen
}

func (sh *spongeHash) BlockSize() int {
	return sh.cur.Rate()
}

