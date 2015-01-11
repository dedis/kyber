package cipher

import (
	//"encoding/hex"
	"github.com/dedis/crypto/abstract"
	"github.com/dedis/crypto/ints"
)

// Sponge is an interface representing a primitive sponge function.
type Sponge interface {

	// XOR src data into sponge's R bits and idx into its C bits,
	// transform its state, and copy resulting R bits into dst.
	// Buffers may overlap and may be short or nil.
	Transform(dst,src,idx []byte)

	// Return the number of data bytes the sponge can aborb in one block.
	Rate() int

	// Return the sponge's secret state capacity in bytes.
	Capacity() int

	// Create a copy of this Sponge with identical state
	Clone() Sponge
}


type spongeCipher struct {

	// Configuration state
	sponge Sponge
	rate int	// number of bytes absorbed and squeezed per block
	padbyte byte	// padding byte to append to last block in message

	// Combined input/output buffer:
	// buf[:pos] contains data bytes to be absorbed;
	// buf[pos:rate] contains as-yet-unused cipherstream bytes.
	buf []byte
	pos int
}

// SpongeCipher builds a general message Cipher from a Sponge function.
func NewSpongeCipher(sponge Sponge, padbyte byte) abstract.Cipher {

	sc := spongeCipher{}
	sc.sponge = sponge
	sc.rate = sponge.Rate()
	sc.padbyte = padbyte
	sc.buf = make([]byte, sc.rate)
	sc.pos = 0
	return &sc
}

func (sc *spongeCipher) parseOptions(options []abstract.Option) bool {
	more := false
	for _, opt := range(options) {
		switch opt {
		case abstract.More: more = true
		default: panic("Unsupported option "+opt.String())
		}
	}
	return more
}

func (sc *spongeCipher) Encrypt(dst, src []byte,
			options ...abstract.Option) abstract.Cipher {

	more := sc.parseOptions(options)
	sp := sc.sponge
	rate := sc.rate
	buf := sc.buf
	pos := sc.pos
	for {
		if pos == rate {
			// process next block
			sp.Transform(buf, buf, nil)
			pos = 0
		}

		n := rate - pos	// remaining bytes in this block
		if len(src) == 0 {
			if len(dst) == 0 {
				break	// done
			}

			// squeeze output only, src is zero bytes
			n = ints.Min(n, len(dst))
			copy(dst[:n], buf[pos:])
			dst = dst[n:]

		} else if len(dst) == 0 {

			// absorb input only
			n = ints.Min(n, len(src))
			for i := 0; i < n; i++ {
				buf[pos + i] ^= src[i]
			}
			src = src[n:]

		} else {

			// squeeze output while absorbing input
			n = ints.Min(n, ints.Min(len(src), len(dst)))
			for i := 0; i < n; i++ {
				buf[pos + i] ^= src[i] // absorb ciphertext
				dst[i] = buf[pos + i] // and output
			}
			src = src[n:]
			dst = dst[n:]
		}
		pos += n
	}

	// pad the final block of a message
	if !more {
		if pos == rate {
			sp.Transform(buf, buf, nil)
			pos = 0
		}

		// XOR in appropriate multi-rate padding
		buf[pos] ^= sc.padbyte
		buf[rate-1] ^= 0x80

		// process last block
		sp.Transform(buf, buf, nil)
		pos = 0
	}

	sc.pos = pos
	return sc
}

func (sc *spongeCipher) Decrypt(dst, src []byte,
			options ...abstract.Option) abstract.Cipher {

	more := sc.parseOptions(options)

	//osrc,odst := src,dst
	//println("Decrypt",more,"\n")

	sp := sc.sponge
	rate := sc.rate
	buf := sc.buf
	pos := sc.pos
	for {
		if pos == rate {
			// process next block
			sp.Transform(buf, buf, nil)
			pos = 0
		}

		n := rate - pos	// remaining bytes in this block
		if len(src) == 0 {
			if len(dst) == 0 {
				break	// done
			}

			// squeeze output only
			n = ints.Min(n, len(dst))
			for i := 0; i < n; i++ {
				dst[i] = buf[pos + i]
				buf[pos + i] = 0
			}
			dst = dst[n:]

		} else if len(dst) == 0 {

			// absorb input only
			n = ints.Min(n, len(src))
			for i := 0; i < n; i++ {
				buf[pos + i] = src[i]
			}
			src = src[n:]

		} else {

			// squeeze output while absorbing input
			n = ints.Min(n, ints.Min(len(src), len(dst)))
			for i := 0; i < n; i++ {
				b := buf[pos + i] // encryption stream
				buf[pos + i] = src[i] // absorb ciphertext
				dst[i] = src[i] ^ b // decrypt
			}
			src = src[n:]
			dst = dst[n:]
		}
		pos += n
	}

	if !more {
		if pos == rate {
			sp.Transform(buf, buf, nil)
			pos = 0
		}

		// append appropriate multi-rate padding
		buf[pos]  = sc.padbyte
		pos++
		for ; pos < rate; pos++ {
			buf[pos] = 0
		}
		buf[rate-1] ^= 0x80

		// process final padded block
		sp.Transform(buf, buf, nil)
		pos = 0
	}

	//println("Decrypted",more,"\n" + hex.Dump(osrc) + "->\n" + hex.Dump(odst))
	sc.pos = pos
	return sc
}

func (sc *spongeCipher) Clone(src []byte) abstract.Cipher {
	nsc := *sc
	nsc.sponge = sc.sponge.Clone()
	nsc.buf = make([]byte, sc.rate)
	copy(nsc.buf, sc.buf)

	if src != nil {
		nsc.Encrypt(nil, src)
	}

	return &nsc
}

func (sc *spongeCipher) KeySize() int {
	return sc.sponge.Capacity() >> 1
}

func (sc *spongeCipher) HashSize() int {
	return sc.sponge.Capacity()
}

func (sc *spongeCipher) BlockSize() int {
	return sc.sponge.Rate()
}

