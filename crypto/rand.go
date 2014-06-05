package main

import (
	"io"
	"math/big"
	"crypto/rand"
)

// An abstract, infinite source of random or pseudo-random bits.
// Like io.Reader but always yields requested # of bytes with no errors.
type Random interface {
	Read(buf []byte)
}

// Choose a uniform random BigInt with a given maximum BitLen.
// If 'exact' is true, choose a BigInt with _exactly_ that BitLen, not less
func BigIntLen(bitlen uint, exact bool, rand Random) *big.Int {
	b := make([]byte, (bitlen+7)/8)
	rand.Read(b)
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
	return new(big.Int).SetBytes(b)
}

// Choose a uniform random BigInt less than a given modulus
func BigIntMod(mod *big.Int, rand Random) *big.Int {
	bitlen := uint(mod.BitLen())
	for {
		i := BigIntLen(bitlen, false, rand)
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

type readrand struct {
	ior io.Reader
}

func (r *readrand) Read(buf []byte) {
	n, err := r.ior.Read(buf)
	if err != nil {
		panic(err)
	}
	if n < len(buf) {
		panic("short read on infinite random stream!?")
	}
}

func ReaderRandom(ior io.Reader) Random {
	r := new(readrand)
	r.ior = ior
	return r
}

var SystemRandom Random = ReaderRandom(rand.Reader)

