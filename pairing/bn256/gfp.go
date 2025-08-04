//go:build !constantTime

package bn256

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"go.dedis.ch/kyber/v4/compatible"
	"golang.org/x/crypto/hkdf"
)

type gfP [4]uint64

func newGFp(x int64) (out *gfP) {
	if x >= 0 {
		out = &gfP{uint64(x)}
	} else {
		out = &gfP{uint64(-x)}
		gfpNeg(out, out)
	}

	montEncode(out, out)
	return out
}

func newGFpFromBigInt(bigInt *compatible.Int) *gfP {
	leftPad32 := func(in []byte) []byte {
		if len(in) > 32 {
			panic("input cannot be more than 32 bytes")
		}

		o := make([]byte, 32)
		copy(o[32-len(in):], in)
		return o
	}

	out := new(gfP)
	out.Unmarshal(leftPad32(bigInt.Bytes()))
	montEncode(out, out)
	return out
}

func hashToBase(msg, dst []byte) *gfP {
	var t [48]byte
	info := []byte{'H', '2', 'C', byte(0), byte(1)}
	r := hkdf.New(sha256.New, msg, dst, info)
	if _, err := r.Read(t[:]); err != nil {
		panic(err)
	}
	var x compatible.Int
	v := x.SetBytes(t[:]).Mod(&x, p).Bytes()
	v32 := [32]byte{}
	for i := len(v) - 1; i >= 0; i-- {
		v32[len(v)-1-i] = v[i]
	}
	u := &gfP{
		binary.LittleEndian.Uint64(v32[0*8 : 1*8]),
		binary.LittleEndian.Uint64(v32[1*8 : 2*8]),
		binary.LittleEndian.Uint64(v32[2*8 : 3*8]),
		binary.LittleEndian.Uint64(v32[3*8 : 4*8]),
	}
	montEncode(u, u)
	return u
}

func (e *gfP) String() string {
	return fmt.Sprintf("%16.16x%16.16x%16.16x%16.16x", e[3], e[2], e[1], e[0])
}

func (e *gfP) Set(f *gfP) {
	e[0] = f[0]
	e[1] = f[1]
	e[2] = f[2]
	e[3] = f[3]
}

func (e *gfP) exp(f *gfP, bits [4]uint64) {
	sum, power := &gfP{}, &gfP{}
	sum.Set(rN1)
	power.Set(f)

	for word := 0; word < 4; word++ {
		for bit := uint(0); bit < 64; bit++ {
			if (bits[word]>>bit)&1 == 1 {
				gfpMul(sum, sum, power)
			}
			gfpMul(power, power, power)
		}
	}

	gfpMul(sum, sum, r3)
	e.Set(sum)
}

func (e *gfP) Invert(f *gfP) {
	e.exp(f, pMinus2)
}

func (e *gfP) Sqrt(f *gfP) {
	// Since p = 4k+3, then e = f^(k+1) is a root of f.
	e.exp(f, pPlus1Over4)
}

func (e *gfP) Marshal(out []byte) {
	for w := uint(0); w < 4; w++ {
		for b := uint(0); b < 8; b++ {
			out[8*w+b] = byte(e[3-w] >> (56 - 8*b))
		}
	}
}

func (e *gfP) Unmarshal(in []byte) {
	for w := uint(0); w < 4; w++ {
		e[3-w] = 0
		for b := uint(0); b < 8; b++ {
			e[3-w] += uint64(in[8*w+b]) << (56 - 8*b)
		}
	}
}

func (e *gfP) BigInt() *compatible.Int {
	bigInt := new(compatible.Int)
	decoded := new(gfP)
	montDecode(decoded, e)
	buf := make([]byte, 32)
	decoded.Marshal(buf)
	bigInt.SetBytes(buf)
	return bigInt
}

func montEncode(c, a *gfP) { gfpMul(c, a, r2) }
func montDecode(c, a *gfP) { gfpMul(c, a, &gfP{1}) }

func sign0(e *gfP) int {
	x := &gfP{}
	montDecode(x, e)
	for w := 3; w >= 0; w-- {
		if x[w] > pMinus1Over2[w] {
			return 1
		} else if x[w] < pMinus1Over2[w] {
			return -1
		}
	}
	return 1
}

func legendre(e *gfP) int {
	f := &gfP{}
	// Since p = 4k+3, then e^(2k+1) is the Legendre symbol of e.
	f.exp(e, pMinus1Over2)

	montDecode(f, f)

	if *f != [4]uint64{} {
		return 2*int(f[0]&1) - 1
	}

	return 0
}
