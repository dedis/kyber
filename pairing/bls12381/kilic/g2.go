//go:build !constantTime

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

// domainG2 is the DST used for hash to curve on G2, this is the default from the RFC.
// This is compatible with the paired library > v18
var domainG2 = []byte("BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_")

func DefaultDomainG2() []byte {
	return domainG2
}

// G2Elt is a kyber.Point holding a G2 point on BLS12-381 curve
type G2Elt struct {
	p *bls12381.PointG2
	// domain separation tag. We treat a 0 len dst as the default value as per the RFC "Tags MUST have nonzero length"
	dst []byte
}

func NullG2(dst ...byte) *G2Elt {
	var p bls12381.PointG2
	return newG2(&p, dst)
}

func newG2(p *bls12381.PointG2, dst []byte) *G2Elt {
	domain := dst
	if bytes.Equal(dst, domainG2) {
		domain = nil
	}
	return &G2Elt{p: p, dst: domain}
}

func (k *G2Elt) Equal(k2 kyber.Point) bool {
	k2g2, ok := k2.(*G2Elt)
	if !ok {
		return false
	}
	return bls12381.NewG2().Equal(k.p, k2g2.p) && bytes.Equal(k.dst, k2g2.dst)
}

func (k *G2Elt) Null() kyber.Point {
	return newG2(bls12381.NewG2().Zero(), k.dst)
}

func (k *G2Elt) Base() kyber.Point {
	return newG2(bls12381.NewG2().One(), k.dst)
}

func (k *G2Elt) Pick(rand cipher.Stream) kyber.Point {
	var dst, src [32]byte
	rand.XORKeyStream(dst[:], src[:])
	return k.Hash(dst[:])
}

func (k *G2Elt) Set(q kyber.Point) kyber.Point {
	k.p.Set(q.(*G2Elt).p)
	return k
}

func (k *G2Elt) Clone() kyber.Point {
	var p bls12381.PointG2
	p.Set(k.p)
	return newG2(&p, k.dst)
}

func (k *G2Elt) EmbedLen() int {
	panic("bls12-381: unsupported operation")
}

func (k *G2Elt) Embed(_ []byte, _ cipher.Stream) kyber.Point {
	panic("bls12-381: unsupported operation")
}

func (k *G2Elt) Data() ([]byte, error) {
	panic("bls12-381: unsupported operation")
}

func (k *G2Elt) Add(a, b kyber.Point) kyber.Point {
	aa := a.(*G2Elt)
	bb := b.(*G2Elt)
	bls12381.NewG2().Add(k.p, aa.p, bb.p)
	return k
}

func (k *G2Elt) Sub(a, b kyber.Point) kyber.Point {
	aa := a.(*G2Elt)
	bb := b.(*G2Elt)
	bls12381.NewG2().Sub(k.p, aa.p, bb.p)
	return k
}

func (k *G2Elt) Neg(a kyber.Point) kyber.Point {
	aa := a.(*G2Elt)
	bls12381.NewG2().Neg(k.p, aa.p)
	return k
}

func (k *G2Elt) Mul(s kyber.Scalar, q kyber.Point) kyber.Point {
	if q == nil {
		q = NullG2(k.dst...).Base()
	}
	bls12381.NewG2().MulScalarBig(k.p, q.(*G2Elt).p, &s.(*mod.Int).V)
	return k
}

// MarshalBinary returns a compressed point, without any domain separation tag information
func (k *G2Elt) MarshalBinary() ([]byte, error) {
	// we need to clone the point because of https://github.com/kilic/bls12-381/issues/37
	// in order to avoid risks of race conditions.
	t := new(bls12381.PointG2).Set(k.p)
	return bls12381.NewG2().ToCompressed(t), nil
}

// UnmarshalBinary populates the point from a compressed point representation.
func (k *G2Elt) UnmarshalBinary(buff []byte) error {
	var err error
	k.p, err = bls12381.NewG2().FromCompressed(buff)
	return err
}

// MarshalTo writes a compressed point to the Writer, without any domain separation tag information
func (k *G2Elt) MarshalTo(w io.Writer) (int, error) {
	buf, err := k.MarshalBinary()
	if err != nil {
		return 0, err
	}
	return w.Write(buf)
}

// UnmarshalFrom populates the point from a compressed point representation read from the Reader.
func (k *G2Elt) UnmarshalFrom(r io.Reader) (int, error) {
	buf := make([]byte, k.MarshalSize())
	n, err := io.ReadFull(r, buf)
	if err != nil {
		return n, err
	}
	return n, k.UnmarshalBinary(buf)
}

func (k *G2Elt) MarshalSize() int {
	return 96
}

func (k *G2Elt) String() string {
	b, _ := k.MarshalBinary()
	return "bls12-381.G2: " + hex.EncodeToString(b)
}

func (k *G2Elt) Hash(m []byte) kyber.Point {
	domain := domainG2
	// We treat a 0 len dst as the default value as per the RFC "Tags MUST have nonzero length"
	if len(k.dst) != 0 {
		domain = k.dst
	}
	pg2, _ := bls12381.NewG2().HashToCurve(m, domain)
	k.p = pg2
	return k
}

func (k *G2Elt) IsInCorrectGroup() bool {
	return bls12381.NewG2().InCorrectSubgroup(k.p)
}
