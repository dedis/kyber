package pbc

import (
	"crypto/cipher"
	"crypto/sha256"
	"hash"
	"io"
	"reflect"

	"github.com/dedis/kyber/abstract"
	"github.com/dfinity/go-dfinity-crypto/bls"

	"github.com/dedis/kyber/cipher/sha3"
)

// Group interface extension to create pairing-capable points.
type PairingGroup interface {
	abstract.Group // Standard Group operations

	PointGT() PointGT // Create new pairing-capable Point
}

// Point interface extension for a point in a pairing target group (GT),
// which supports the Pairing operation.
type PointGT interface {
	abstract.Point // Standard Point operations

	// Compute the pairing of two points p1 and p2,
	// which must be in the associated groups G1 and G2 respectively.
	Pairing(p1, p2 abstract.Point) abstract.Point
}

// PairingSuite represents the basic functionalities needed to use pairing based
// cryptography.
type PairingSuite interface {
	G1() abstract.Group
	G2() abstract.Group
	GT() PairingGroup
}

type g1group struct {
	common
	curve int
}
type g2group struct {
	common
	curve int
}
type gtgroup struct {
	common
	p *Pairing
}

// A Pairing object represents a pairing-based cryptography environment,
// consisting of two source groups G1 and G2 and a target group GT.
// All of these groups support the standard Group API operations.
// In addition, the GT group supports the new Pairing operation,
// via the PointGT extension to the Point interface.
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
	p.g1.curve = curve
	p.g2.curve = curve
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

func (p *Pairing) G1() abstract.Suite {
	return &p.g1
}

func (p *Pairing) G2() abstract.Suite {
	return &p.g2
}

func (p *Pairing) GT() PairingGroup {
	return &p.gt
}

func (p *Pairing) Cipher(key []byte, options ...interface{}) abstract.Cipher {
	return sha3.NewShakeCipher128(key, options...)
}

func (p *Pairing) Hash() hash.Hash {
	return sha256.New()
}
func (g *g1group) String() string {
	return curveName(g.curve) + "_G1"
}

func (g *g1group) PointLen() int {
	return g.Point().MarshalSize()
}

func (g *g1group) Point() abstract.Point {
	return newPointG1(generator(g.curve, 0))
}

func (g *g2group) String() string {
	return curveName(g.curve) + "_G2"
}

func (g *g2group) PointLen() int {
	return g.Point().MarshalSize()
}

func (g *g2group) Point() abstract.Point {
	return newPointG2(generator(g.curve, 1))
}

func (g *gtgroup) String() string {
	return curveName(g.p.curve) + "_GT"
}

func (g *gtgroup) PointLen() int {
	return g.Point().MarshalSize()
}

func (g *gtgroup) Point() abstract.Point {
	return newPointGT(g.p)
}

func (g *gtgroup) PointGT() PointGT {
	return g.Point().(PointGT)
}

type common struct{}

func (c *common) Hash() hash.Hash {
	return sha256.New()
}

func (c *common) Cipher(key []byte, options ...interface{}) abstract.Cipher {
	return sha3.NewShakeCipher128(key, options...)
}

func (c *common) PrimeOrder() bool {
	return true
}

func (c *common) ScalarLen() int {
	return bls.GetOpUnitSize() * 8
}

func (c *common) Scalar() abstract.Scalar {
	return NewScalar()
}

func (c *common) Read(r io.Reader, objs ...interface{}) error {
	panic("Not implemented")
}

func (c *common) Write(w io.Writer, objs ...interface{}) error {
	panic("not implemented")
}

func (c *common) New(t reflect.Type) interface{} {
	panic("not implemented")
}

func (c *common) NewKey(r cipher.Stream) abstract.Scalar {
	return NewScalar()
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
