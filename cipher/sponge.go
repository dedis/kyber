package cipher

import (
	"fmt"
	"log"
	//"encoding/hex"
	"github.com/dedis/crypto/abstract"
	"github.com/dedis/crypto/ints"
	"github.com/dedis/crypto/random"
)

// Sponge is an interface representing a primitive sponge function.
type Sponge interface {

	// XOR src data into sponge's R bits and idx into its C bits,
	// transform its state, and copy resulting R bits into dst.
	// Buffers may overlap and may be short or nil.
	Transform(dst, src, idx []byte)

	// Return the number of data bytes the sponge can aborb in one block.
	Rate() int

	// Return the sponge's secret state capacity in bytes.
	Capacity() int

	// Create a copy of this Sponge with identical state
	Clone() Sponge
}

// Padding is an Option to configure the padding and domain-separation byte
// to be used with a Sponge cipher.
type Padding byte

func (p Padding) String() string {
	return fmt.Sprintf("Padding: %x", byte(p))
}

type spongeCipher struct {

	// Configuration state
	sponge Sponge
	rate   int                // number of bytes absorbed and squeezed per block
	dir    abstract.Direction // encrypt or decrypt
	pad    byte               // padding byte to append to last block in message

	// Combined input/output buffer:
	// buf[:pos] contains data bytes to be absorbed;
	// buf[pos:rate] contains as-yet-unused cipherstream bytes.
	buf []byte
	pos int
}

func (sc *spongeCipher) parseOptions(options []interface{}) bool {
	more := false
	for _, opt := range options {
		switch v := opt.(type) {
		case abstract.More:
			more = true
		case abstract.Direction:
			sc.dir = v
		case Padding:
			sc.pad = byte(v)
		default:
			log.Panicf("Unsupported option %v", opt)
		}
	}
	return more
}

// SpongeCipher builds a general message Cipher from a Sponge function.
func NewSpongeCipher(sponge Sponge, key []byte, options ...interface{}) abstract.Cipher {
	sc := spongeCipher{}
	sc.sponge = sponge
	sc.rate = sponge.Rate()
	sc.pad = byte(0x7f) // default, unused by standards
	sc.buf = make([]byte, sc.rate)
	sc.pos = 0
	sc.parseOptions(options)

	if key == nil {
		key = random.Bytes(sponge.Capacity(), random.Stream)
	}
	if len(key) > 0 {
		sc.Crypt(nil, key)
	}

	return &sc
}

func (sc *spongeCipher) encrypt(dst, src []byte, more bool) abstract.Cipher {
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

		n := rate - pos // remaining bytes in this block
		if len(src) == 0 {
			if len(dst) == 0 {
				break // done
			}

			// squeeze output only
			n = ints.Min(n, len(dst))
			for i := 0; i < n; i++ {
				dst[i] = buf[pos+i]
				buf[pos+i] = 0
			}
			dst = dst[n:]

		} else if len(dst) == 0 {

			// absorb input only
			n = ints.Min(n, len(src))
			for i := 0; i < n; i++ {
				buf[pos+i] = src[i]
			}
			src = src[n:]

		} else {

			// squeeze output while absorbing input
			n = ints.Min(n, ints.Min(len(src), len(dst)))
			for i := 0; i < n; i++ {
				b := buf[pos+i]     // encryption stream
				buf[pos+i] = src[i] // absorb ciphertext
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
		buf[pos] = sc.pad
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

func (sc *spongeCipher) decrypt(dst, src []byte, more bool) abstract.Cipher {
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

		n := rate - pos // remaining bytes in this block
		if len(src) == 0 {
			if len(dst) == 0 {
				break // done
			}

			// squeeze output only, src is zero bytes
			n = ints.Min(n, len(dst))
			copy(dst[:n], buf[pos:])
			dst = dst[n:]

		} else if len(dst) == 0 {

			// absorb input only
			n = ints.Min(n, len(src))
			for i := 0; i < n; i++ {
				buf[pos+i] ^= src[i]
			}
			src = src[n:]

		} else {

			// squeeze output while absorbing input
			n = ints.Min(n, ints.Min(len(src), len(dst)))
			for i := 0; i < n; i++ {
				buf[pos+i] ^= src[i] // absorb ciphertext
				dst[i] = buf[pos+i]  // and output
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

		// append appropriate multi-rate padding
		buf[pos] = sc.pad
		pos++
		for ; pos < rate; pos++ {
			buf[pos] = 0
		}
		buf[rate-1] ^= 0x80

		// process last block
		sp.Transform(buf, buf, nil)
		pos = 0
	}

	sc.pos = pos
	return sc
}

func (sc *spongeCipher) Crypt(dst, src []byte,
	options ...interface{}) abstract.Cipher {
	more := sc.parseOptions(options)
	if sc.dir >= 0 {
		return sc.encrypt(dst, src, more)
	} else {
		return sc.decrypt(dst, src, more)
	}
}

func (sc *spongeCipher) Read(dst []byte) (n int, err error) {
	return CipherRead(sc, dst)
}

func (sc *spongeCipher) Write(src []byte) (n int, err error) {
	return CipherWrite(sc, src)
}

func (sc *spongeCipher) XORKeyStream(dst, src []byte) {
	CipherXORKeyStream(sc, dst, src)
}

func (sc *spongeCipher) Clone(src []byte) abstract.Cipher {
	nsc := *sc
	nsc.sponge = sc.sponge.Clone()
	nsc.buf = make([]byte, sc.rate)
	copy(nsc.buf, sc.buf)

	if src != nil {
		nsc.Crypt(nil, src)
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
