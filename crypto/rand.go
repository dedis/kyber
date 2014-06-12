package crypto

import (
	"math/big"
	"crypto/rand"
	"crypto/cipher"
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

// Steal value from DSA, which uses recommendation from FIPS 186-3
const numMRTests = 64

func IsPrime(i *big.Int) bool {
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

// virtual "stream cipher" that just generates
// fresh cryptographically strong random bits
var RandomStream cipher.Stream = new(randstream)

