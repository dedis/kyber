package crypto

import (
	"fmt"
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
	if len(b) < l {		// pad leading zero bytes if necessary
		b = append(make([]byte,l-len(b)), b...)
	}
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

// Validate the parameters for a Schnorr group
func (g *SchnorrGroup) Valid() bool {

	// Make sure both P and Q are prime
	if !IsPrime(g.P) || !IsPrime(g.Q) {
		return false
	}

	// Validate the equation P = QR+1
	n := new(big.Int)
	n.Mul(g.Q,g.R)
	n.Add(n,one)
	if n.Cmp(g.P) != 0 {
		return false
	}

	// Validate the generator G
	if g.G.Cmp(one) <= 0 || n.Exp(g.G, g.Q, g.P).Cmp(one) != 0 {
		return false
	}

	return true
}

func (g *SchnorrGroup) SetParams(P,Q,R,G *big.Int) {
	g.P = P
	g.Q = Q
	g.R = R
	g.G = G
	if !g.Valid() {
		panic("SetParams: bad Schnorr group parameters")
	}

}

// Initialize Schnorr group parameters for a quadratic residue group
func (g *SchnorrGroup) QuadraticResidueGroup(bitlen uint, rand cipher.Stream) {
	g.R = two

	// pick primes p,q such that p = 2q+1
	fmt.Printf("Generating %d-bit QR group", bitlen)
	for i := 0; ; i++ {
		if i > 1000 {
			print(".")
			i = 0
		}

		// First pick a prime Q
		b := RandomBits(bitlen-1, true, rand)
		b[len(b)-1] |= 1			// must be odd
		g.Q = new(big.Int).SetBytes(b)
		//println("q?",hex.EncodeToString(g.Q.Bytes()))
		if !IsPrime(g.Q) {
			continue
		}

		// Does the corresponding P come out prime too?
		g.P = new(big.Int)
		g.P.Mul(g.Q,two)
		g.P.Add(g.P,one)
		//println("p?",hex.EncodeToString(g.P.Bytes()))
		if uint(g.P.BitLen()) == bitlen && IsPrime(g.P) {
			break
		}
	}
	println()
	println("p",g.P.String())
	println("q",g.Q.String())

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
	println("g",g.G.String())
}

