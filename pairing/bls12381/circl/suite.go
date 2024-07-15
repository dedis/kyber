package circl

import (
	"crypto/cipher"
	"crypto/sha256"
	"hash"
	"io"

	bls12381 "github.com/cloudflare/circl/ecc/bls12381"
	"go.dedis.ch/kyber/v4"
	"go.dedis.ch/kyber/v4/pairing"
	"go.dedis.ch/kyber/v4/util/random"
	"go.dedis.ch/kyber/v4/xof/blake2xb"
)

var _ pairing.Suite = Suite{}

type Suite struct{}

func NewSuite() (s Suite) { return }

func (s Suite) String() string  { return "bls12381" }
func (s Suite) G1() kyber.Group { return G1 }
func (s Suite) G2() kyber.Group { return G2 }
func (s Suite) GT() kyber.Group { return GT }

func (s Suite) Pair(p1, p2 kyber.Point) kyber.Point {
	aa, bb := p1.(*G1Elt), p2.(*G2Elt)
	return &GTElt{*bls12381.Pair(&aa.inner, &bb.inner)}
}
func (s Suite) ValidatePairing(p1, p2, p3, p4 kyber.Point) bool {
	a, b := p1.(*G1Elt), p2.(*G2Elt)
	c, d := p3.(*G1Elt), p4.(*G2Elt)
	out := bls12381.ProdPairFrac(
		[]*bls12381.G1{&a.inner, &c.inner},
		[]*bls12381.G2{&b.inner, &d.inner},
		[]int{1, -1},
	)
	return out.IsIdentity()
}

func (s Suite) Read(_ io.Reader, _ ...interface{}) error {
	panic("Suite.Read(): deprecated in drand")
}

func (s Suite) Write(_ io.Writer, _ ...interface{}) error {
	panic("Suite.Write(): deprecated in drand")
}

func (s Suite) Hash() hash.Hash {
	return sha256.New()
}

func (s Suite) XOF(seed []byte) kyber.XOF {
	return blake2xb.New(seed)
}

func (s Suite) RandomStream() cipher.Stream {
	return random.New()
}
