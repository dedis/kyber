package crypto

import (
	"math/big"
	"crypto/rand"
	"crypto/cipher"
	"encoding/binary"
)

// Choose a uniform random BigInt with a given maximum BitLen.
// If 'exact' is true, choose a BigInt with _exactly_ that BitLen, not less
func RandomBits(bitlen uint, exact bool, rand cipher.Stream) []byte {
	b := make([]byte, (bitlen+7)/8)
	rand.XORKeyStream(b,b)
	highbits := bitlen & 7
	if highbits != 0 {
		b[0] &= ^(0xff << highbits)
	}
	if exact {
		if highbits != 0 {
			b[0] |= 1 << (highbits-1)
		} else {
			b[0] |= 0x80
		}
	}
	return b
}

// Choose a uniform random byte
func RandomByte(rand cipher.Stream) byte {
	b := RandomBits(8, false, rand)
	return b[0]
}

// Choose a uniform random uint8
func RandomUint8(rand cipher.Stream) uint8 {
	b := RandomBits(8, false, rand)
	return uint8(b[0])
}

// Choose a uniform random uint16
func RandomUint16(rand cipher.Stream) uint16 {
	b := RandomBits(16, false, rand)
	return binary.BigEndian.Uint16(b)
}

// Choose a uniform random uint32
func RandomUint32(rand cipher.Stream) uint32 {
	b := RandomBits(32, false, rand)
	return binary.BigEndian.Uint32(b)
}

// Choose a uniform random uint64
func RandomUint64(rand cipher.Stream) uint64 {
	b := RandomBits(64, false, rand)
	return binary.BigEndian.Uint64(b)
}

// Choose a uniform random BigInt less than a given modulus
func RandomBigInt(mod *big.Int, rand cipher.Stream) *big.Int {
	bitlen := uint(mod.BitLen())
	i := new(big.Int)
	for {
		i.SetBytes(RandomBits(bitlen, false, rand))
		if i.Sign() > 0 && i.Cmp(mod) < 0 {
			return i
		}
	}
}

// RandomReader wraps a Stream to produce an io.Reader
// that simply produces [pseudo-]random bits from the Stream when read.
// Calls to both Read() and XORKeyStream() may be made on the RandomReader,
// and may be interspersed.
type RandomReader struct {
	cipher.Stream
}

// Read [pseudo-]random bytes from the underlying Stream.
func (r RandomReader) Read(dst []byte) (n int, err error) {
	for i := range(dst) {
		dst[i] = 0
	}
	r.Stream.XORKeyStream(dst,dst)
	return len(dst),nil
}


// Steal value from DSA, which uses recommendation from FIPS 186-3
const numMRTests = 64

// Probabilistically test whether a big integer is prime.
func isPrime(i *big.Int) bool {
	return i.ProbablyPrime(numMRTests)
}

type randstream struct {
}

func (r *randstream) XORKeyStream(dst, src []byte) {
	l := len(dst)
	if len(src) != l {
		panic("XORKeyStream: mismatched buffer lengths")
	}

	buf := make([]byte,l)
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

// Standard virtual "stream cipher" that just generates
// fresh cryptographically strong random bits.
var RandomStream cipher.Stream = new(randstream)

