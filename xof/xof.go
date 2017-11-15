package xof

import (
	"crypto/cipher"

	"github.com/dedis/kyber/util/ints"
)

// Sponge is an interface representing a primitive sponge function.
type Sponge interface {

	// XOR src data into sponge's internal state,
	// transform its state, and copy resulting state into dst.
	// Buffers must be either Rate or Rate+Capacity bytes long.
	Transform(dst, src []byte)

	// Return the number of data bytes the sponge can aborb in one block.
	Rate() int

	// Return the sponge's secret state capacity in bytes.
	Capacity() int
}

// Xof is an interface for extendable-output functions.
// The Xof is not suffiently keyed until Rate() bytes have been
// Absorb()ed.
// TODO: better explanation when I understand it better
type Xof interface {
	cipher.Stream
	Absorb(key []byte)
	Extract(dst []byte)
	// Rate returns the rate of the underlying sponge.
	Rate() int
}

type xofSponge struct {
	// Configuration state
	sponge Sponge

	//rate   int  // Bytes absorbed and squeezed per block
	//cap    int  // Bytes of secret internal state
	//pad    byte // padding byte to append to last block in message

	// Combined input/output buffer:
	// buf[:pos] contains data bytes to be absorbed;
	// buf[pos:rate] contains as-yet-unused cipherstream bytes.
	// buf[rate:rate+cap] contains current domain-separation bytes.
	buf []byte
	pos int
}

func FromSponge(sponge Sponge, options ...interface{}) Xof {
	x := &xofSponge{sponge: sponge}
	x.buf = make([]byte, x.sponge.Rate()+x.sponge.Capacity())
	// TODO: options
	return x
}

func (x *xofSponge) Rate() int { return x.sponge.Rate() }

func (x *xofSponge) XORKeyStream(dst, src []byte) {
	// This behavior is specified in the cipher.Stream interface.
	if len(dst) < len(src) {
		panic("not enough room in dst")
	}

	// Iterate through src, using the key stream available,
	// making more as needed, until src is consumed.
	for len(src) > 0 {
		// Get more bytes to extract
		if x.pos == x.sponge.Rate() {
			x.sponge.Transform(x.buf, x.buf[:x.sponge.Rate()])
			x.pos = 0
			println("xform, pos", x.pos)
		}

		// Sub-slice src to indicate the next block we are doing
		n := ints.Min(x.sponge.Rate()-x.pos, len(src))
		println("n", n)
		src2 := src[:n]
		for i := range src2 { // XOR-encrypt from src2 to dst
			dst[i] = src2[i] ^ x.buf[x.pos+i]
		}
		x.pos += n
		println("pos", x.pos)
		// mark those bytes consumed
		src = src[n:]
	}
}

func (x *xofSponge) Absorb(key []byte) {
	for len(key) > 0 {
		n := ints.Min(x.sponge.Rate()-x.pos, len(key))
		copy(x.buf[x.pos:], key[0:n])
		key = key[n:]
		x.pos += n
		if x.pos == x.sponge.Rate() {
			x.sponge.Transform(x.buf, x.buf[:x.sponge.Rate()])
		}
	}
}

func (x *xofSponge) Extract(dst []byte) {
	b := make([]byte, len(dst))
	x.XORKeyStream(b, b)
	copy(dst, b)
}
