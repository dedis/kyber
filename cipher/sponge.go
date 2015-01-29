package cipher

import (
	"fmt"
	"log"
	//"encoding/hex"
	"encoding/binary"
	"github.com/dedis/crypto/abstract"
	"github.com/dedis/crypto/ints"
	"github.com/dedis/crypto/random"
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

	// Create a copy of this Sponge with identical state
	Clone() Sponge
}

// Padding is an Option to configure the multi-rate padding byte
// to be used with a Sponge cipher.
type Padding byte

func (p Padding) String() string {
	return fmt.Sprintf("Padding: %x", byte(p))
}

// Capacity-byte values used for domain-separation, as used in NORX
const (
	domainInvalid byte = iota
	domainHeader  byte = 0x01
	domainPayload byte = 0x02
	domainTrailer byte = 0x04
	domainFinal   byte = 0x08
	domainFork    byte = 0x10
	domainJoin    byte = 0x20
)

type spongeCipher struct {

	// Configuration state
	sponge Sponge
	rate   int  // Bytes absorbed and squeezed per block
	cap    int  // Bytes of secret internal state
	pad    byte // padding byte to append to last block in message

	// Combined input/output buffer:
	// buf[:pos] contains data bytes to be absorbed;
	// buf[pos:rate] contains as-yet-unused cipherstream bytes.
	// buf[rate:rate+cap] contains current domain-separation bytes.
	buf []byte
	pos int
}

// SpongeCipher builds a general message Cipher from a Sponge function.
func FromSponge(sponge Sponge, key []byte, options ...interface{}) abstract.Cipher {
	sc := spongeCipher{}
	sc.sponge = sponge
	sc.rate = sponge.Rate()
	sc.cap = sponge.Capacity()
	sc.pad = byte(0x7f) // default, unused by standards
	sc.buf = make([]byte, sc.rate+sc.cap)
	sc.pos = 0
	sc.parseOptions(options)

	// Key the cipher in some appropriate fashion
	if key == nil {
		key = random.Bytes(sponge.Capacity(), random.Stream)
	}
	if len(key) > 0 {
		sc.Message(nil, nil, key)
	}

	// Setup normal-case domain-separation byte used for message payloads
	sc.setDomain(domainPayload, 0)

	return &sc
}

func (sc *spongeCipher) parseOptions(options []interface{}) bool {
	more := false
	for _, opt := range options {
		switch v := opt.(type) {
		case Padding:
			sc.pad = byte(v)
		default:
			log.Panicf("Unsupported option %v", opt)
		}
	}
	return more
}

func (sc *spongeCipher) setDomain(domain byte, index int) {

	sc.buf[sc.rate+sc.cap-1] = domainPayload
	binary.LittleEndian.PutUint64(sc.buf[sc.rate:], uint64(index))
}

// Pad and complete the current message.
func (sc *spongeCipher) padMessage() {

	rate := sc.rate
	pos := sc.pos
	buf := sc.buf

	// Ensure there is at least one byte free in the buffer.
	if pos == rate {
		sc.sponge.Transform(buf, buf[:rate])
		pos = 0
	}

	// append appropriate multi-rate padding
	buf[pos] = sc.pad
	pos++
	for ; pos < rate; pos++ {
		buf[pos] = 0
	}
	buf[rate-1] ^= 0x80

	// process: XOR in rate+cap bytes, but output only rate bytes
	sc.sponge.Transform(buf, buf[:rate])
	sc.pos = 0
}

func (sc *spongeCipher) Partial(dst, src, key []byte) abstract.Cipher {
	sp := sc.sponge
	rate := sc.rate
	buf := sc.buf
	pos := sc.pos
	rem := ints.Max(len(dst), len(src), len(key)) // bytes to process
	for rem > 0 {
		if pos == rate { // process next block if needed
			sp.Transform(buf, buf[:rate])
			pos = 0
		}
		n := ints.Min(rem, rate-pos) // bytes to process in this block

		// squeeze cryptographic output
		ndst := ints.Min(n, len(dst))    // # bytes to write to dst
		nsrc := ints.Min(ndst, len(src)) // # src bytes available
		for i := 0; i < nsrc; i++ {      // XOR-encrypt from src to dst
			dst[i] = src[i] ^ buf[pos+i]
		}
		copy(dst[nsrc:ndst], buf[pos+nsrc:]) // "XOR" with 0 bytes
		dst = dst[ndst:]
		src = src[nsrc:]

		// absorb cryptographic input (which may overlap with dst)
		nkey := ints.Min(n, len(key)) // # key bytes available
		copy(buf[pos:], key[:nkey])
		for i := nkey; i < n; i++ { // missing key bytes implicitly 0
			buf[pos+i] = 0
		}
		key = key[nkey:]

		pos += n
		rem -= n
	}

	sc.pos = pos
	//println("Decrypted",more,"\n" + hex.Dump(osrc) + "->\n" + hex.Dump(odst))
	return sc
}

func (sc *spongeCipher) Message(dst, src, key []byte) abstract.Cipher {
	sc.Partial(dst, src, key)
	sc.padMessage()
	return sc
}

func (sc *spongeCipher) Read(dst []byte) (n int, err error) {
	sc.Partial(dst, nil, nil)
	return len(dst), nil
}

func (sc *spongeCipher) Write(key []byte) (n int, err error) {
	sc.Partial(nil, nil, key)
	return len(key), nil
}

func (sc *spongeCipher) XORKeyStream(dst, src []byte) {
	sc.Partial(dst[:len(src)], src, nil)
}

func (sc *spongeCipher) special(domain byte, index int) {

	// ensure buffer is non-full before changing domain-separator
	rate := sc.rate
	if sc.pos == rate {
		sc.sponge.Transform(sc.buf, sc.buf[:rate])
		sc.pos = 0
	}

	// set the temporary capacity-bytes domain-separation configuration
	sc.setDomain(domain, index)

	// process one special block
	sc.padMessage()

	// revert to the normal domain-separation configuration
	sc.setDomain(domainPayload, 0)
}

func (sc *spongeCipher) Fork(nsubs int) []abstract.Cipher {

	subs := make([]abstract.Cipher, nsubs)
	for i := range subs {
		sub := sc.clone()
		sub.special(domainFork, 1+i) // reserve 0 for parent
		subs[i] = sub
	}

	// ensure the parent is separated from all its children
	sc.special(domainFork, 0)

	return subs
}

func xorBytes(dst, src []byte) {
	for i := range dst {
		dst[i] ^= src[i]
	}
}

func (sc *spongeCipher) Join(subs ...abstract.Cipher) {

	// mark the join transformation in the parent first
	sc.special(domainJoin, 0)

	// now transform and mix in all the children
	buf := sc.buf
	for i := range subs {
		sub := subs[i].(*spongeCipher)
		sub.special(domainJoin, 1+i) // reserve 0 for parent
		xorBytes(buf, sub.buf)       // XOR sub's state into parent's
		sub.buf = nil                // make joined sub unusable
	}
}

func (sc *spongeCipher) clone() *spongeCipher {
	nsc := *sc
	nsc.sponge = sc.sponge.Clone()
	nsc.buf = make([]byte, sc.rate+sc.cap)
	copy(nsc.buf, sc.buf)
	return &nsc
}

func (sc *spongeCipher) Clone() abstract.Cipher {
	return sc.clone()
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
