package kilic

import (
	"bytes"
	"crypto/cipher"
	"encoding/hex"
	"io"

	bls12381 "github.com/kilic/bls12-381"
	"go.dedis.ch/kyber/v4"
	"go.dedis.ch/kyber/v4/group/mod"
)

// domainG1 is the DST used for hash to curve on G1, this is the default from the RFC.
var domainG1 = []byte("BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_NUL_")

func DefaultDomainG1() []byte {
	return domainG1
}

// G1Elt is a kyber.Point holding a G1 point on BLS12-381 curve
type G1Elt struct {
	p *bls12381.PointG1
	// domain separation tag. We treat a 0 len dst as the default value as per the RFC "Tags MUST have nonzero length"
	dst []byte

	kyber.Point
	kyber.HashablePoint
}

func NullG1(dst ...byte) *G1Elt {
	var p bls12381.PointG1
	return newG1(&p, dst)
}
func newG1(p *bls12381.PointG1, dst []byte) *G1Elt {
	domain := dst
	if bytes.Equal(dst, domainG1) {
		domain = nil
	}
	return &G1Elt{p: p, dst: domain}
}

func (k *G1Elt) Equal(k2 kyber.Point) bool {
	k2g1, ok := k2.(*G1Elt)
	if !ok {
		return false
	}
	return bls12381.NewG1().Equal(k.p, k2g1.p) && bytes.Equal(k.dst, k2g1.dst)
}

func (k *G1Elt) Null() kyber.Point {
	return newG1(bls12381.NewG1().Zero(), k.dst)
}

func (k *G1Elt) Base() kyber.Point {
	return newG1(bls12381.NewG1().One(), k.dst)
}

func (k *G1Elt) Pick(rand cipher.Stream) kyber.Point {
	var dst, src [32]byte
	rand.XORKeyStream(dst[:], src[:])
	return k.Hash(dst[:])
}

func (k *G1Elt) Set(q kyber.Point) kyber.Point {
	k.p.Set(q.(*G1Elt).p)
	return k
}

func (k *G1Elt) Clone() kyber.Point {
	var p bls12381.PointG1
	p.Set(k.p)
	return newG1(&p, k.dst)
}

func (k *G1Elt) EmbedLen() int {
	panic("bls12-381: unsupported operation")
}

func (k *G1Elt) Embed(_ []byte, _ cipher.Stream) kyber.Point {
	panic("bls12-381: unsupported operation")
}

func (k *G1Elt) Data() ([]byte, error) {
	panic("bls12-381: unsupported operation")
}

func (k *G1Elt) Add(a, b kyber.Point) kyber.Point {
	aa := a.(*G1Elt)
	bb := b.(*G1Elt)
	bls12381.NewG1().Add(k.p, aa.p, bb.p)
	return k
}

func (k *G1Elt) Sub(a, b kyber.Point) kyber.Point {
	aa := a.(*G1Elt)
	bb := b.(*G1Elt)
	bls12381.NewG1().Sub(k.p, aa.p, bb.p)
	return k
}

func (k *G1Elt) Neg(a kyber.Point) kyber.Point {
	aa := a.(*G1Elt)
	bls12381.NewG1().Neg(k.p, aa.p)
	return k
}

func (k *G1Elt) Mul(s kyber.Scalar, q kyber.Point) kyber.Point {
	if q == nil {
		q = NullG1(k.dst...).Base()
	}
	bls12381.NewG1().MulScalarBig(k.p, q.(*G1Elt).p, &s.(*mod.Int).V)
	return k
}

// MarshalBinary returns a compressed point, without any domain separation tag information
func (k *G1Elt) MarshalBinary() ([]byte, error) {
	// we need to clone the point because of https://github.com/kilic/bls12-381/issues/37
	// in order to avoid risks of race conditions.
	t := new(bls12381.PointG1).Set(k.p)
	return bls12381.NewG1().ToCompressed(t), nil
}

// UnmarshalBinary populates the point from a compressed point representation.
func (k *G1Elt) UnmarshalBinary(buff []byte) error {
	var err error
	k.p, err = bls12381.NewG1().FromCompressed(buff)
	return err
}

// MarshalTo writes a compressed point to the Writer, without any domain separation tag information
func (k *G1Elt) MarshalTo(w io.Writer) (int, error) {
	buf, err := k.MarshalBinary()
	if err != nil {
		return 0, err
	}
	return w.Write(buf)
}

// UnmarshalFrom populates the point from a compressed point representation read from the Reader.
func (k *G1Elt) UnmarshalFrom(r io.Reader) (int, error) {
	buf := make([]byte, k.MarshalSize())
	n, err := io.ReadFull(r, buf)
	if err != nil {
		return n, err
	}
	return n, k.UnmarshalBinary(buf)
}

func (k *G1Elt) MarshalSize() int {
	return 48
}

func (k *G1Elt) String() string {
	b, _ := k.MarshalBinary()
	return "bls12-381.G1: " + hex.EncodeToString(b)
}

func (k *G1Elt) Hash(m []byte) kyber.Point {
	domain := domainG1
	// We treat a 0 len dst as the default value as per the RFC "Tags MUST have nonzero length"
	if len(k.dst) != 0 {
		domain = k.dst
	}
	p, _ := bls12381.NewG1().HashToCurve(m, domain)
	k.p = p
	return k
}

func (k *G1Elt) IsInCorrectGroup() bool {
	return bls12381.NewG1().InCorrectSubgroup(k.p)
}
