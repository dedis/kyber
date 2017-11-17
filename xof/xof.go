package xof

import (
	"github.com/dedis/kyber"
)

type xofSponge struct {
	sponge kyber.Sponge
	// Combined input/output buffer:
	// buf[:pos] contains data bytes to be absorbed;
	// buf[pos:rate] contains as-yet-unused cipherstream bytes.
	// buf[rate:rate+cap] contains current domain-separation bytes.
	buf []byte
	pos int
}

// NewFromSponge makes a new Xof based on the given sponge implementation.
func NewFromSponge(sponge kyber.Sponge) kyber.Xof {
	x := &xofSponge{sponge: sponge}
	x.buf = make([]byte, x.sponge.Rate()+x.sponge.Capacity())
	return x
}

// NewByName makes a new Xof with the named sponge. If the sponge is unknown, it panics.
func NewByName(name string) kyber.Xof {
	return NewFromSponge(sponges[name]())
}

// New makes a new Xof using the default sponge type.
func New() kyber.Xof {
	return NewFromSponge(sponges[defaultSponge]())
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
		}

		// Sub-slice src to indicate the next block we are doing
		n := min(x.sponge.Rate()-x.pos, len(src))
		src2 := src[:n]
		for i := range src2 { // XOR-encrypt from src2 to dst
			dst[i] = src2[i] ^ x.buf[x.pos+i]
		}
		x.pos += n
		// mark those bytes consumed/produced
		src = src[n:]
		dst = dst[n:]
	}
}

func (x *xofSponge) Absorb(key []byte) {
	for len(key) > 0 {
		if x.pos == x.sponge.Rate() {
			x.sponge.Transform(x.buf, x.buf[:x.sponge.Rate()])
			x.pos = 0
		}
		n := min(x.sponge.Rate()-x.pos, len(key))
		copy(x.buf[x.pos:], key[0:n])
		key = key[n:]
		x.pos += n
	}
	// Pad with zeros until pos == x.sponge.Rate()
	for ; x.pos < x.sponge.Rate(); x.pos++ {
		x.buf[x.pos] = 0
	}
}

func (x *xofSponge) Extract(dst []byte) {
	b := make([]byte, len(dst))
	x.XORKeyStream(b, b)
	copy(dst, b)
}

func (x0 *xofSponge) Clone() kyber.Xof {
	var x1 = *x0
	x1.sponge = x0.sponge.Clone()
	x1.buf = make([]byte, len(x0.buf))
	copy(x1.buf, x0.buf)
	return &x1
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
