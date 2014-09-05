package crypto

import (
	"fmt"
	"errors"
	"math/big"
	"crypto/dsa"
	"crypto/cipher"
	//"encoding/hex"
)


type schnorrPoint struct {
	big.Int 
	g *SchnorrGroup
}

func (p *schnorrPoint) String() string { return p.Int.String() }

func (p *schnorrPoint) Equal(p2 Point) bool {
	return p.Int.Cmp(&p2.(*schnorrPoint).Int) == 0
}

func (p *schnorrPoint) Null() Point {
	p.Int.SetInt64(1)
	return p
}

func (p *schnorrPoint) Base(rand cipher.Stream) Point {
	if rand == nil {
		// use the well-known generator
		p.Int.Set(p.g.G)
	} else {
		// pick a new pseudo-random generator
		for {
			p.Pick(nil, rand)		// pick a random point
			p.Exp(&p.Int, p.g.R, p.g.P)	// find a generator
			if p.Cmp(one) != 0 {
				break			// got one
			}
			// retry
		}
	}
	return p
}

func (p *schnorrPoint) Valid() bool {
	return p.Int.Sign() > 0 && p.Int.Cmp(p.g.P) < 0 &&
		new(big.Int).Exp(&p.Int, p.g.Q, p.g.P).Cmp(one) == 0
}

func (p *schnorrPoint) PickLen() int {
	// Reserve at least 8 most-significant bits for randomness,
	// and the least-significant 16 bits for embedded data length.
	return (p.g.P.BitLen() - 8 - 16) / 8
}

// Pick a point containing a variable amount of embedded data.
// Remaining bits comprising the point are chosen randomly.
// This will only work efficiently for quadratic residue groups!
func (p *schnorrPoint) Pick(data []byte, rand cipher.Stream) (Point, []byte) {

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
			return p, data[dl:]
		}
	}
}

// Extract embedded data from a Schnorr group element
func (p *schnorrPoint) Data() ([]byte,error) {
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

func (p *schnorrPoint) Add(a,b Point) Point {
	p.Int.Mul(&a.(*schnorrPoint).Int, &b.(*schnorrPoint).Int)
	p.Int.Mod(&p.Int, p.g.P)
	return p
}

func (p *schnorrPoint) Sub(a,b Point) Point {
	binv := new(big.Int).ModInverse(&b.(*schnorrPoint).Int, p.g.P)
	p.Int.Mul(&a.(*schnorrPoint).Int, binv)
	p.Int.Mod(&p.Int, p.g.P)
	return p
}

func (p *schnorrPoint) Neg(a Point) Point {
	p.Int.ModInverse(&a.(*schnorrPoint).Int, p.g.P)
	return p
}

func (p *schnorrPoint) Mul(b Point, s Secret) Point {
	if b == nil {
		return p.Base(nil).Mul(p,s)
	}
	p.Int.Exp(&b.(*schnorrPoint).Int, &s.(*ModInt).V, p.g.P)
	return p
}

func (p *schnorrPoint) Len() int {
	return (p.g.P.BitLen()+7)/8
}

func (p *schnorrPoint) Encode() []byte {
	b := p.Int.Bytes()	// may be shorter than len(buf)
	if pre := p.Len()-len(b); pre != 0 {
		return append(make([]byte, pre), b...)
	}
	return b
}

func (p *schnorrPoint) Decode(data []byte) error {
	p.Int.SetBytes(data)
	if !p.Valid() {
		return errors.New("invalid Schnorr group element")
	}
	return nil
}



/*
A SchnorrGroup represents a DSA-style modular integer arithmetic group,
defined by two primes P and Q and an integer R, such that P = Q*R+1.
Points in a SchnorrGroup are R-residues modulo P,
and Secrets are integer exponents modulo the group order Q.

In traditional DSA groups P is typically much larger than Q,
and hence use a large multiple R.
This is done to minimize the computational cost of modular exponentiation
while maximizing security against known classes of attacks:
P must be on the order of thousands of bits long
while for security Q is believed to require only hundreds of bits.
Such computation-optimized groups are suitable
for Diffie-Hellman agreement, DSA or ElGamal signatures, etc.,
which depend on Point.Mul() and homomorphic properties.

However, Schnorr groups with large R are less suitable for
public-key cryptographic techniques that require choosing Points
pseudo-randomly or to contain embedded data,
as required by ElGamal encryption for example, or by Dissent's
hash-generator construction for verifiable DC-nets.
For such purposes quadratic residue groups are more suitable -
representing the special case where R=2 and hence P=2Q+1.
As a result, the Point.Pick() method should be expected to work efficiently
ONLY on quadratic residue groups in which R=2.
*/
type SchnorrGroup struct {
	dsa.Parameters
	R *big.Int
}

func (g *SchnorrGroup) String() string {
	return fmt.Sprintf("Schnorr%d", g.P.BitLen())
}

// Return the number of bytes in the encoding of a Secret
// for this Schnorr group.
func (g *SchnorrGroup) SecretLen() int { return (g.Q.BitLen()+7)/8 }

// Create a Secret associated with this Schnorr group,
// with an initial value of nil.
func (g *SchnorrGroup) Secret() Secret {
	return NewModInt(0, g.Q)
}

// Return the number of bytes in the encoding of a Point
// for this Schnorr group.
func (g *SchnorrGroup) PointLen() int { return (g.P.BitLen()+7)/8 }

// Create a Point associated with this Schnorr group,
// with an initial value of nil.
func (g *SchnorrGroup) Point() Point {
	p := new(schnorrPoint)
	p.g = g
	return p
}

// Returns the order of this Schnorr group, namely the prime Q.
func (g *SchnorrGroup) Order() *big.Int {
	return g.Q
}

// Validate the parameters for a Schnorr group,
// checking that P and Q are prime, P=Q*R+1,
// and that G is a valid generator for this group.
func (g *SchnorrGroup) Valid() bool {

	// Make sure both P and Q are prime
	if !isPrime(g.P) || !isPrime(g.Q) {
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

// Explicitly initialize a SchnorrGroup with given parameters.
func (g *SchnorrGroup) SetParams(P,Q,R,G *big.Int) {
	g.P = P
	g.Q = Q
	g.R = R
	g.G = G
	if !g.Valid() {
		panic("SetParams: bad Schnorr group parameters")
	}

}

// Initialize Schnorr group parameters for a quadratic residue group,
// by picking primes P and Q such that P=2Q+1
// and the smallest valid generator G for this group.
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
		if !isPrime(g.Q) {
			continue
		}

		// Does the corresponding P come out prime too?
		g.P = new(big.Int)
		g.P.Mul(g.Q,two)
		g.P.Add(g.P,one)
		//println("p?",hex.EncodeToString(g.P.Bytes()))
		if uint(g.P.BitLen()) == bitlen && isPrime(g.P) {
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

