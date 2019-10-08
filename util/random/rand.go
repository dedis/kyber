// Package random provides facilities for generating
// random or pseudorandom cryptographic objects.
package random

import (
	"bytes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha512"
	"io"
	"math/big"

	"go.dedis.ch/kyber/v3/xof/blake2xb"
)

// Bits chooses a uniform random BigInt with a given maximum BitLen.
// If 'exact' is true, choose a BigInt with _exactly_ that BitLen, not less
func Bits(bitlen uint, exact bool, rand cipher.Stream) []byte {
	b := make([]byte, (bitlen+7)/8)
	rand.XORKeyStream(b, b)
	highbits := bitlen & 7
	if highbits != 0 {
		b[0] &= ^(0xff << highbits)
	}
	if exact {
		if highbits != 0 {
			b[0] |= 1 << (highbits - 1)
		} else {
			b[0] |= 0x80
		}
	}
	return b
}

// Int chooses a uniform random big.Int less than a given modulus
func Int(mod *big.Int, rand cipher.Stream) *big.Int {
	bitlen := uint(mod.BitLen())
	i := new(big.Int)
	for {
		i.SetBytes(Bits(bitlen, false, rand))
		if i.Sign() > 0 && i.Cmp(mod) < 0 {
			return i
		}
	}
}

// Bytes fills a slice with random bytes from rand.
func Bytes(b []byte, rand cipher.Stream) {
	rand.XORKeyStream(b, b)
}

type randstream struct {
}

func (r *randstream) XORKeyStream(dst, src []byte) {
	// This function works only on local data, so it is
	// safe against race conditions, as long as crypto/rand
	// is as well. (It is.)

	l := len(dst)
	if len(src) != l {
		panic("XORKeyStream: mismatched buffer lengths")
	}

	buf := make([]byte, l)
	n, err := rand.Read(buf)
	if err != nil {
		panic(err)
	}
	if n < len(buf) {
		panic("short read on infinite random stream!?")
	}

	for i := 0; i < l; i++ {
		dst[i] = src[i] ^ buf[i]
	}
}

// New returns a new cipher.Stream that gets random data from Go's crypto/rand package.
// The resulting cipher.Stream can be used in multiple threads.
func New() cipher.Stream {
	return &randstream{}
}

// READER_BYTES is how many bytes we expect from each source
const READER_BYTES = 32

// MixedrandHash is the hash used in XORKeyStream to mix all entropy sources together.
// sha512 is chosen as its digest is 64 bytes long, matching the length of blake2xb's seed.
var MixedrandHash = sha512.New

type mixedrandstream struct {
	Readers []io.Reader
}

func (r *mixedrandstream) XORKeyStream(dst, src []byte) {

	l := len(dst)
	if len(src) != l {
		panic("XORKeyStream: mismatched buffer lengths")
	}

	// try to read 32 bytes from all readers and write them in a buffer
	var b bytes.Buffer
	var nerr int
	buff := make([]byte, READER_BYTES)
	for _, reader := range r.Readers {
		n, err := io.ReadFull(reader, buff)
		if err != nil {
			nerr++
		}
		b.Write(buff[:n])
	}

	// we are ok with few sources being insecure (i.e., providing less than
	// READER_BYTES bytes), but not all of them
	if nerr == len(r.Readers) {
		panic("all readers failed")
	}

	// create the XOF output, with hash of collected data as seed
	h := MixedrandHash()
	h.Write(b.Bytes())
	seed := h.Sum(nil)
	blake2 := blake2xb.New(seed)
	blake2.XORKeyStream(dst, src)
}

// NewMixedStream returns a new cipher.Stream that gets random data from the given
// readers. If no reader was provided, Go's crypto/rand package is used.
// In order to use every source, it tries to read 32 bytes from each, and mix it
// all together into a string of valid length via hashing. This string is then
// used as a seed for blake2, which is used to perform the final XOR.
func NewMixedStream(readers ...io.Reader) cipher.Stream {
	if len(readers) == 0 {
		readers = []io.Reader{rand.Reader}
	}
	return &mixedrandstream{readers}
}
