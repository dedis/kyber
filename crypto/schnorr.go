package crypto

import (
	"errors"
	"math/big"
	"crypto/dsa"
	"crypto/cipher"
	//"encoding/hex"
)


var one *big.Int = new(big.Int).SetInt64(1)
var two *big.Int = new(big.Int).SetInt64(2)


type SchnorrSecret struct {
	i big.Int 
	g *SchnorrGroup
}

func (s *SchnorrSecret) Encode() []byte { return s.i.Bytes() }
func (s *SchnorrSecret) Decode(buf []byte) Secret {
	s.i.SetBytes(buf)
	return s
}
func (s *SchnorrSecret) String() string { return s.i.String() }
func (s *SchnorrSecret) Equal(s2 Secret) bool {
	return s.i.Cmp(&s2.(*SchnorrSecret).i) == 0
}
func (s *SchnorrSecret) Add(a,b Secret) Secret {
	s.i.Add(&a.(*SchnorrSecret).i,&b.(*SchnorrSecret).i)
	s.i.Mod(&s.i, s.g.Q)
	return s
}
func (s *SchnorrSecret) Pick(rand cipher.Stream) Secret {
	s.i.Set(RandomBigInt(s.g.Q,rand))
	return s
}

type SchnorrPoint struct {
	big.Int 
	g *SchnorrGroup
}

func (p *SchnorrPoint) String() string { return p.Int.String() }

func (p *SchnorrPoint) Equal(p2 Point) bool {
	return p.Int.Cmp(&p2.(*SchnorrPoint).Int) == 0
}

func (p *SchnorrPoint) Base() Point {
	p.Int.Set(p.g.G)
	return p
}

func (p *SchnorrPoint) Valid() bool {
	return p.Int.Sign() > 0 && p.Int.Cmp(p.g.P) < 0 &&
		new(big.Int).Exp(&p.Int, p.g.Q, p.g.P).Cmp(one) == 0
}

func (p *SchnorrPoint) PickLen() int {
	// Reserve at least 8 most-significant bits for randomness,
	// and the least-significant 16 bits for embedded data length.
	return (p.g.P.BitLen() - 8 - 16) / 8
}

// Pick a point containing a variable amount of embedded data.
// Remaining bits comprising the point are chosen randomly.
// This will only work efficiently for quadratic residue groups!
func (p *SchnorrPoint) Pick(data []byte, rand cipher.Stream) []byte {

	l := p.g.PointLen()
	dl := p.PickLen()
	if dl > len(data) {
		dl = len(data)
	}

	for {
		b := RandomBits(uint(p.g.P.BitLen()), false, rand)
		if data != nil {
			b[l-1] = byte(dl)	// Encode length in low 16 bits
			b[l-2] = byte(dl >> 8)
			copy(b[l-dl-2:l-2],data) // Copy in embedded data
		}
		p.Int.SetBytes(b)
		if p.Valid() {
			return data[dl:]
		}
	}
}

// Extract embedded data from a Schnorr group element
func (p *SchnorrPoint) Data() ([]byte,error) {
	b := p.Int.Bytes()
	l := p.g.PointLen()
	dl := int(b[l-2])<<8 + int(b[l-1])
	if dl > p.PickLen() {
		return nil,errors.New("invalid embedded data length")
	}
	return b[l-dl-2:l-2],nil
}

func (p *SchnorrPoint) Encrypt(b Point, s Secret) Point {
	p.Int.Exp(&b.(*SchnorrPoint).Int, &s.(*SchnorrSecret).i, p.g.P)
	return p
}

func (g *SchnorrGroup) EncodePoint(p Point) []byte {
	return p.(*SchnorrPoint).Int.Bytes()
}

func (p *SchnorrPoint) Encode() []byte {
	return p.Bytes()
}

func (p *SchnorrPoint) Decode(data []byte) error {
	p.Int.SetBytes(data)
	if !p.Valid() {
		return errors.New("invalid Schnorr group element")
	}
	return nil
}




type SchnorrGroup struct {
	dsa.Parameters
	R *big.Int
}

func (g *SchnorrGroup) SecretLen() int { return (g.Q.BitLen()+7)/8 }

func (g *SchnorrGroup) Secret() Secret {
	s := new(SchnorrSecret)
	s.g = g
	return s
}

func (g *SchnorrGroup) PointLen() int { return (g.P.BitLen()+7)/8 }

func (g *SchnorrGroup) Point() Point {
	p := new(SchnorrPoint)
	p.g = g
	return p
}

func (g *SchnorrGroup) Order() *big.Int {
	return g.Q
}


// Initialize Schnorr group parameters for a quadratic residue group
func (g *SchnorrGroup) QuadraticResidueGroup(bitlen uint, rand cipher.Stream) {
	g.R = two

	// pick primes p,q such that p = 2q+1
	for {
		g.Q = new(big.Int).SetBytes(RandomBits(bitlen-1, true, rand))

		g.P = new(big.Int)
		g.P.Mul(g.Q,two)
		g.P.Add(g.P,one)

		if uint(g.P.BitLen()) == bitlen &&
			IsPrime(g.P) && IsPrime(g.Q) {
			break
		}
	}
	println("p = ",g.P.String())
	println("q = ",g.Q.String())

	// pick standard generator G
	h := new(big.Int).Set(two)
	g.G = new(big.Int)
	for {
		g.G.Exp(h,two,g.P)
		if g.G.Cmp(one) != 0 {
			break
		}
		h.Add(h, one)
	}
	println("g = ",g.G.String())
}

