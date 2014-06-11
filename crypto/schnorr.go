package crypto

import (
	"errors"
	"math/big"
	"crypto/dsa"
	"crypto/cipher"
)


type SchnorrSecret struct {
	big.Int 
	g *SchnorrGroup
}

func (s *SchnorrSecret) Encode() []byte { return s.Bytes() }
func (s *SchnorrSecret) Decode(buf []byte) Secret {
	s.SetBytes(buf)
	return s
}
func (s *SchnorrSecret) String() string { return s.Int.String() }
func (s *SchnorrSecret) Equal(s2 Secret) bool {
	return s.Int.Cmp(&s2.(*SchnorrSecret).Int) == 0
}

type SchnorrPoint struct {
	big.Int 
	g *SchnorrGroup
}

func (p *SchnorrPoint) Encode() []byte { return p.Bytes() }
func (p *SchnorrPoint) Decode(buf []byte) Point {
	p.SetBytes(buf)
	return p
}
func (p *SchnorrPoint) String() string { return p.Int.String() }
func (p *SchnorrPoint) Equal(p2 Point) bool {
	return p.Int.Cmp(&p2.(*SchnorrPoint).Int) == 0
}


type SchnorrGroup struct {
	dsa.Parameters
	R *big.Int
}


var one *big.Int = new(big.Int).SetInt64(1)
var two *big.Int = new(big.Int).SetInt64(2)


func (g *SchnorrGroup) SecretLen() int { return (g.Q.BitLen()+7)/8 }

func (g *SchnorrGroup) RandomSecret(rand cipher.Stream) Secret {
	s := new(SchnorrSecret)
	s.Int.Set(BigIntMod(g.Q,rand))
	return s
}

func (g *SchnorrGroup) AddSecret(x, y Secret) Secret {
	s := new(SchnorrSecret)
	s.Int.Add(&x.(*SchnorrSecret).Int,&y.(*SchnorrSecret).Int)
	s.Int.Mod(&s.Int, g.Q)
	return s
}


func (g *SchnorrGroup) PointLen() int { return (g.P.BitLen()+7)/8 }

func (g *SchnorrGroup) IdentityPoint() Point {
	p := new(SchnorrPoint)
	p.Int.Set(one)
	return p
}

func (g *SchnorrGroup) BasePoint() Point {
	p := new(SchnorrPoint)
	p.Int.Set(g.G)
	return p
}

func (g *SchnorrGroup) ValidPoint(p Point) bool {
	sp := p.(*SchnorrPoint)
	return sp.Int.Sign() > 0 && sp.Int.Cmp(g.P) < 0 &&
		new(big.Int).Exp(&sp.Int, g.Q, g.P).Cmp(one) == 0
}

// This will only work efficiently for quadratic residue groups!
func (g *SchnorrGroup) RandomPoint(rand cipher.Stream) Point {
	p := new(SchnorrPoint)
	for {
		p.Int.Set(BigIntMod(g.Q, rand))
		if g.ValidPoint(p) {
			return p
		}
	}
}

/*
func GenDSAGroup(sizes dsa.ParameterSizes, rand Random) (err error) {
	g := new(SchnorrGroup)
	var pl, ql : int
	switch sizes {
	case dsa.L1024N160:
		g.PL = 1024
		g.QL = 160
	case dsa.L2048N224:
		g.PL = 2048
		g.QL = 224
	case dsa.L2048N256:
		g.PL = 2048
		g.QL = 256
	case dsa.L3072N256:
		g.PL = 3072
		g.QL = 256
	default:
		return errors.New("Unrecognized DSA parameter sizes")
	}

	err = dsa.GenerateParameters(g, rand, sizes)
	if err {
		return err
	}

	XXX R
}
*/

func (g *SchnorrGroup) EncryptPoint(p Point, s Secret) Point {
	e := new(SchnorrPoint)
	e.Int.Exp(&p.(*SchnorrPoint).Int, &s.(*SchnorrSecret).Int, g.P)
	return e
}

func (g *SchnorrGroup) EncodePoint(p Point) []byte {
	return p.(*SchnorrPoint).Int.Bytes()
}

func (g *SchnorrGroup) DecodePoint(data []byte) (Point,error)	{
	p := new(SchnorrPoint)
	p.Int.SetBytes(data)
	if !g.ValidPoint(p) {
		return nil, errors.New("invalid Schnorr group element")
	}

	return p, nil
}

func (g *SchnorrGroup) GroupOrder() *big.Int {
	return g.Q
}


// Initialize Schnorr group parameters for a quadratic residue group
func (g *SchnorrGroup) QuadraticResidueGroup(bitlen uint, rand cipher.Stream) {
	g.R = two

	// pick primes p,q such that p = 2q+1
	for {
		g.Q = BigIntLen(bitlen-1, true, rand)

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

/*	general residue group generator, not sure if we need it
func GenResidueGroup(bitlen int, r *big.Int, rand Random) *SchnorrGroup {
	g := new(SchnorrGroup)
	g.R.Set(r)

	pb := make([]byte, (bitlen+7)/8)
	for {
		p := BigIntLen(uint(bitlen), true, rand)
		...
	}
}
*/

func TestSchnorrGroup() {
	sg := new(SchnorrGroup)
	sg.QuadraticResidueGroup(128, RandomStream)
	TestGroup(sg)		// Generic group tests

	// Some Schnorr group specific tests

	// Check identity point and group order
	s1 := sg.RandomSecret(RandomStream)
	p1 := sg.EncryptPoint(sg.BasePoint(),s1)
	if !sg.EncryptPoint(sg.IdentityPoint(),s1).Equal(sg.IdentityPoint()) {
		panic("IdentityPoint doesn't act as an identity")
	}
	so := new(SchnorrSecret)
	so.Int.Set(sg.GroupOrder())
	if !sg.EncryptPoint(p1,so).Equal(sg.IdentityPoint()) {
		panic("GroupOrder doesn't work")
	}
}

