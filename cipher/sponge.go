package cipher

import (
	"github.com/dedis/crypto/abstract"
	"github.com/dedis/crypto/ints"
)

type spongeCipher struct {

	// Configuration state
	sponge abstract.Sponge
	rate int	// number of bytes absorbed and squeezed per block

	// Combined input/output buffer:
	// buf[:pos] contains data bytes to be absorbed;
	// buf[pos:rate] contains as-yet-unused cipherstream bytes.
	buf []byte
	pos int
}

// SpongeCipher builds a general message Cipher from a sponge function.
func SpongeCipher(sponge abstract.Sponge) Cipher {

	sc := spongeCipher{}
	sc.sponge = sponge
	sc.rate = sponge.Rate()
	sc.buf = make([]byte, sc.rate)
	sc.pos = 0
	return &sc
}

func (sc *spongeCipher) parseOptions(options []Option) bool {
	more := false
	for _, opt := range(options) {
		if opt == More {
			more = true
		} else {
			panic("Unsupported option "+opt.String())
		}
	}
	return more
}

func (sc *spongeCipher) Encrypt(dst, src []byte, options ...Option) Cipher {

	more := sc.parseOptions(options)
	sp := sc.sponge
	rate := sc.rate
	pos := sc.pos
	for {
		n := rate - pos	// remaining bytes in this block
		if n == 0 {
			// process next block
			sp.Transform(sc.buf, sc.buf, nil)
			pos = 0
			n = rate
		}

		if len(src) == 0 {
			if len(dst) == 0 {
				break	// done
			}

			// squeeze output only, src is zero bytes
			n = ints.Min(n, len(dst))
			copy(dst[:n], sc.buf[pos:])
			pos += n

		} else if len(dst) == 0 {

			// absorb input only
			n = ints.Min(n, len(src))
			for i := 0; i < n; i++ {
				sc.buf[pos + i] ^= src[i]
			}
			pos += n

		} else {

			// squeeze output while absorbing input
			n = ints.Min(n, ints.Min(len(src), len(dst)))
			for i := 0; i < n; i++ {
				sc.buf[pos + i] ^= src[i] // absorb ciphertext
				dst[i] = sc.buf[pos + i] // and output
			}
			pos += n
		}
	}

	if more {
	// XXX pad
	}

	sc.pos = pos
	return sc
}

func (sc *spongeCipher) Decrypt(dst, src []byte, options ...Option) Cipher {

	more := sc.parseOptions(options)
	sp := sc.sponge
	rate := sc.rate
	pos := sc.pos
	for {
		n := rate - pos	// remaining bytes in this block
		if n == 0 {
			// process next block
			sp.Transform(sc.buf, sc.buf, nil)
			pos = 0
			n = rate
		}

		if len(src) == 0 {
			if len(dst) == 0 {
				break	// done
			}

			// squeeze output only
			n = ints.Min(n, len(dst))
			for i := 0; i < n; i++ {
				dst[i] = sc.buf[pos + i]
				sc.buf[pos + i] = 0
			}
			pos += n

		} else if len(dst) == 0 {

			// absorb input only
			n = ints.Min(n, len(src))
			for i := 0; i < n; i++ {
				sc.buf[pos + i] = src[i]
			}
			pos += n

		} else {

			// squeeze output while absorbing input
			n = ints.Min(n, ints.Min(len(src), len(dst)))
			for i := 0; i < n; i++ {
				b := sc.buf[pos + i] // cipherstream
				sc.buf[pos + i] = src[i] // absorb ciphertext
				dst[i] = src[i] ^ b // decrypt
			}
			pos += n
		}
	}
	sc.pos = pos

	if more {
	// XXX pad
	}

	return sc
}

func (sc *spongeCipher) Clone(src []byte) Cipher {
	if sc.pos != sc.rate {
		panic("cannot clone a Cipher mid-message")
	}

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

