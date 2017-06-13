package pbc

import (
	"crypto/cipher"
	"dfinity/crypto/bls"

	"gopkg.in/dedis/kyber.v1"
)

// Group interface extension to create pairing-capable points.
type PairingGroup interface {
	kyber.Group // Standard Group operations

	PairingPoint() PairingPoint // Create new pairing-capable Point
}

// Point interface extension for a point in a pairing target group (GT),
// which supports the Pairing operation.
type PairingPoint interface {
	kyber.Point // Standard Point operations

	// Compute the pairing of two points p1 and p2,
	// which must be in the associated groups G1 and G2 respectively.
	Pairing(p1, p2 kyber.Point) kyber.Point
}

type g1group struct{ p *Pairing }
type g2group struct{ p *Pairing }
type gtgroup struct{ p *Pairing }

// A Pairing object represents a pairing-based cryptography environment,
// consisting of two source groups G1 and G2 and a target group GT.
// All of these groups support the standard Group API operations.
// In addition, the GT group supports the new Pairing operation,
// via the PairingPoint extension to the Point interface.
// The input groups G1 and G2 may be identical or different,
// as indicated by the Symmetric() method.
type Pairing struct {
	curve int
	g1    g1group
	g2    g2group
	gt    gtgroup
}

// NewPairing returns a new initialized curve.
// XXX It is currently UNDEFINED to declare multiple pairing since the C lib uses a global
// variable underneath.
func NewPairing(curve int) *Pairing {
	ok := curve == CurveFp254BNb || curve == CurveFp382_1 || curve == CurveFp382_2
	if !ok {
		panic("pairing: unsupported curve")
	}
	bls.Init(curve)
	p := &Pairing{curve: curve}
	p.g1.p = p
	p.g2.p = p
	p.gt.p = p
	return p
}

func NewPairingFp254BNb() *Pairing {
	return NewPairing(CurveFp254BNb)
}

func NewPairingFp382_1() *Pairing {
	return NewPairing(CurveFp382_1)
}

func NewPairingFp382_2() *Pairing {
	return NewPairing(CurveFp382_2)
}

func (p *Pairing) G1() kyber.Group {
	return &p.g1
}

func (p *Pairing) G2() kyber.Group {
	return &p.g2
}

func (p *Pairing) GT() PairingGroup {
	return &p.gt
}

func (g *g1group) String() string {
	return curveName(g.p.curve) + "_G1"
}

func (g *g1group) ScalarLen() int {
	return bls.GetOpUnitSize() * 8
}

func (g *g1group) Scalar() kyber.Scalar {
	return NewScalar()
}

func (g *g1group) PointLen() int {
	return g.Point().MarshalSize()
}

func (g *g1group) Point() kyber.Point {
	return newPointG1(generator(g.p.curve, 0))
}

func (g *g1group) PrimeOrder() bool {
	return true
}

func (g *g1group) NewKey(rand cipher.Stream) kyber.Scalar {
	return NewScalar().Pick(rand)
}

func (g *g2group) String() string {
	return curveName(g.p.curve) + "_G2"
}

func (g *g2group) ScalarLen() int {
	return bls.GetOpUnitSize() * 8
}

func (g *g2group) Scalar() kyber.Scalar {
	return NewScalar()
}

func (g *g2group) PointLen() int {
	return g.Point().MarshalSize()
}

func (g *g2group) Point() kyber.Point {
	return newPointG2(generator(g.p.curve, 1))
}

func (g *g2group) PrimeOrder() bool {
	return true
}

func (g *g2group) NewKey(rand cipher.Stream) kyber.Scalar {
	return NewScalar().Pick(rand)
}

func (g *gtgroup) String() string {
	return curveName(g.p.curve) + "_GT"
}

func (g *gtgroup) ScalarLen() int {
	return bls.GetOpUnitSize() * 8
}

func (g *gtgroup) Scalar() kyber.Scalar {
	return NewScalar()
}

func (g *gtgroup) PointLen() int {
	return g.Point().MarshalSize()
}

func (g *gtgroup) Point() kyber.Point {
	return newPointGT(generator(g.p.curve, 3))
}

func (g *gtgroup) PairingPoint() PairingPoint {
	return g.Point().(PairingPoint)
}

func (g *gtgroup) PrimeOrder() bool {
	panic("not implemented yet")
}

func (g *gtgroup) NewKey(rand cipher.Stream) kyber.Scalar {
	return NewScalar().Pick(rand)
}

func curveName(curve int) string {
	switch curve {
	case CurveFp254BNb:
		return "Fp254Nb"
	case CurveFp382_1:
		return "Fp382_1"
	case CurveFp382_2:
		return "Fp382_2"
	default:
		panic("pairing curve unknown")
	}
}

func generator(curve, group int) string {
	var gens [2]string
	switch curve {
	case CurveFp254BNb:
		gens[0] = Fp254_G1_Base_Str
		gens[1] = Fp254_G2_Base_Str
	case CurveFp382_1:
		gens[0] = Fp382_1_G1_Base_Str
		gens[1] = Fp382_1_G2_Base_Str
	case CurveFp382_2:
		gens[0] = Fp382_2_G1_Base_Str
		gens[1] = Fp382_2_G2_Base_Str
	default:
		panic("pairing curve unknown")
	}
	return gens[group]
}
