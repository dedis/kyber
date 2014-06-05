package main

import (
	"errors"
	"math/big"
	"crypto/dsa"
//	"code.google.com/p/go.crypto/curve25519"
)


type SchnorrGroup struct {
	dsa.Parameters
	R *big.Int
}


var one *big.Int = new(big.Int).SetInt64(1)
var two *big.Int = new(big.Int).SetInt64(2)


func (g *SchnorrGroup) SecretLen() int { return (g.Q.BitLen()+7)/8 }

func (g *SchnorrGroup) RandomSecret(rand Random) *Secret {
	s := new(Secret)
	s.Int.Set(BigIntMod(g.Q,rand))
	return s
}

func (g *SchnorrGroup) AddSecret(x, y *Secret) *Secret {
	s := new(Secret)
	s.Int.Add(&x.Int,&y.Int)
	s.Int.Mod(&s.Int, g.Q)
	return s
}


func (g *SchnorrGroup) PointLen() int { return (g.P.BitLen()+7)/8 }

func (g *SchnorrGroup) IdentityPoint() *Point {
	p := new(Point)
	p.Int.Set(one)
	return p
}

func (g *SchnorrGroup) BasePoint() *Point {
	p := new(Point)
	p.Int.Set(g.G)
	return p
}

func (g *SchnorrGroup) ValidPoint(p *Point) bool {
	return p.Int.Sign() > 0 && p.Int.Cmp(g.P) < 0 &&
		new(big.Int).Exp(&p.Int, g.Q, g.P).Cmp(one) == 0
}

// This will only work efficiently for quadratic residue groups!
func (g *SchnorrGroup) RandomPoint(rand Random) *Point {
	p := new(Point)
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

func (g *SchnorrGroup) EncryptPoint(p *Point, s *Secret) *Point {
	e := new(Point)
	e.Int.Exp(&p.Int, &s.Int, g.P)
	return e
}

func (g *SchnorrGroup) EncodePoint(p *Point) []byte {
	return p.Int.Bytes()
}

func (g *SchnorrGroup) DecodePoint(data []byte) (*Point,error)	{
	p := new(Point)
	p.Int.SetBytes(data)
	if !g.ValidPoint(p) {
		return nil, errors.New("invalid Schnorr group element")
	}

	return p, nil
}

func (g *SchnorrGroup) GroupOrder() *big.Int {
	return g.Q
}


func GenQuadraticResidueGroup(bitlen uint, rand Random) *SchnorrGroup {
	g := new(SchnorrGroup)
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

	return g
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
	sg := GenQuadraticResidueGroup(128, SystemRandom)
	TestGroup(sg)
}


