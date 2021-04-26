package bls12381

import (
	"crypto/cipher"
	"crypto/sha256"
	"encoding/hex"
	"io"

	bls12381 "github.com/kilic/bls12-381"
	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/kyber/v3/group/mod"
)

// pointG1 is a kyber.Point holding a G1 point on BLS12-381 curve
type pointG1 struct {
	p *bls12381.PointG1
}

func nullpointG1() *pointG1 {
	var p bls12381.PointG1
	return newPointG1(&p)
}

func newPointG1(p *bls12381.PointG1) *pointG1 {
	return &pointG1{p: p}
}

func (k *pointG1) Equal(k2 kyber.Point) bool {
	return bls12381.NewG1().Equal(k.p, k2.(*pointG1).p)
}

func (k *pointG1) Null() kyber.Point {
	return newPointG1(bls12381.NewG1().Zero())
}

func (k *pointG1) Base() kyber.Point {
	return newPointG1(bls12381.NewG1().One())
}

func (k *pointG1) Pick(rand cipher.Stream) kyber.Point {
	var dst, src [32]byte
	rand.XORKeyStream(dst[:], src[:])
	return k.Hash(dst[:])
}

func (k *pointG1) Set(q kyber.Point) kyber.Point {
	k.p.Set(q.(*pointG1).p)
	return k
}

func (k *pointG1) Clone() kyber.Point {
	var p bls12381.PointG1
	p.Set(k.p)
	return newPointG1(&p)
}

func (k *pointG1) EmbedLen() int {
	panic("bls12-381: unsupported operation")
}

func (k *pointG1) Embed(data []byte, rand cipher.Stream) kyber.Point {
	panic("bls12-381: unsupported operation")
}

func (k *pointG1) Data() ([]byte, error) {
	panic("bls12-381: unsupported operation")
}

func (k *pointG1) Add(a, b kyber.Point) kyber.Point {
	aa := a.(*pointG1)
	bb := b.(*pointG1)
	bls12381.NewG1().Add(k.p, aa.p, bb.p)
	return k
}

func (k *pointG1) Sub(a, b kyber.Point) kyber.Point {
	aa := a.(*pointG1)
	bb := b.(*pointG1)
	bls12381.NewG1().Sub(k.p, aa.p, bb.p)
	return k
}

func (k *pointG1) Neg(a kyber.Point) kyber.Point {
	aa := a.(*pointG1)
	bls12381.NewG1().Neg(k.p, aa.p)
	return k
}

func (k *pointG1) Mul(s kyber.Scalar, q kyber.Point) kyber.Point {
	if q == nil {
		q = nullpointG1().Base()
	}
	bls12381.NewG1().MulScalarBig(
		k.p,
		q.(*pointG1).p,
		&s.(*mod.Int).V,
	)
	return k
}

func (k *pointG1) MarshalBinary() ([]byte, error) {
	return bls12381.NewG1().ToCompressed(k.p), nil
}

func (k *pointG1) UnmarshalBinary(buff []byte) error {
	var err error
	k.p, err = bls12381.NewG1().FromCompressed(buff)
	return err
}

func (k *pointG1) MarshalTo(w io.Writer) (int, error) {
	buf, err := k.MarshalBinary()
	if err != nil {
		return 0, err
	}
	return w.Write(buf)
}

func (k *pointG1) UnmarshalFrom(r io.Reader) (int, error) {
	buf := make([]byte, k.MarshalSize())
	n, err := io.ReadFull(r, buf)
	if err != nil {
		return n, err
	}
	return n, k.UnmarshalBinary(buf)
}

func (k *pointG1) MarshalSize() int {
	return 48
}

func (k *pointG1) String() string {
	b, _ := k.MarshalBinary()
	return "bls12-381.G1: " + hex.EncodeToString(b)
}

func (k *pointG1) Hash(m []byte) kyber.Point {
	p, _ := bls12381.NewG1().HashToCurve(m, Domain)
	k.p = p
	return k

}

func (k *pointG1) IsInCorrectGroup() bool {
	return bls12381.NewG1().InCorrectSubgroup(k.p)
}

// Domain comes from the ciphersuite used by the RFC of this name compatible
// with the paired library > v18
var Domain = []byte("BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_")

// pointG2 is a kyber.Point holding a G2 point on BLS12-381 curve
type pointG2 struct {
	p *bls12381.PointG2
}

func nullpointG2() *pointG2 {
	var p bls12381.PointG2
	return newPointG2(&p)
}

func newPointG2(p *bls12381.PointG2) *pointG2 {
	return &pointG2{p: p}
}

func (k *pointG2) Equal(k2 kyber.Point) bool {
	return bls12381.NewG2().Equal(k.p, k2.(*pointG2).p)
}

func (k *pointG2) Null() kyber.Point {
	return newPointG2(bls12381.NewG2().Zero())
}

func (k *pointG2) Base() kyber.Point {
	return newPointG2(bls12381.NewG2().One())
}

func (k *pointG2) Pick(rand cipher.Stream) kyber.Point {
	var dst, src [32]byte
	rand.XORKeyStream(dst[:], src[:])
	return k.Hash(dst[:])
}

func (k *pointG2) Set(q kyber.Point) kyber.Point {
	k.p.Set(q.(*pointG2).p)
	return k
}

func (k *pointG2) Clone() kyber.Point {
	var p bls12381.PointG2
	p.Set(k.p)
	return newPointG2(&p)
}

func (k *pointG2) EmbedLen() int {
	panic("bls12-381: unsupported operation")
}

func (k *pointG2) Embed(data []byte, rand cipher.Stream) kyber.Point {
	panic("bls12-381: unsupported operation")
}

func (k *pointG2) Data() ([]byte, error) {
	panic("bls12-381: unsupported operation")
}

func (k *pointG2) Add(a, b kyber.Point) kyber.Point {
	aa := a.(*pointG2)
	bb := b.(*pointG2)
	bls12381.NewG2().Add(k.p, aa.p, bb.p)
	return k
}

func (k *pointG2) Sub(a, b kyber.Point) kyber.Point {
	aa := a.(*pointG2)
	bb := b.(*pointG2)
	bls12381.NewG2().Sub(k.p, aa.p, bb.p)
	return k
}

func (k *pointG2) Neg(a kyber.Point) kyber.Point {
	aa := a.(*pointG2)
	bls12381.NewG2().Neg(k.p, aa.p)
	return k
}

func (k *pointG2) Mul(s kyber.Scalar, q kyber.Point) kyber.Point {
	if q == nil {
		q = nullpointG2().Base()
	}
	bls12381.NewG2().MulScalarBig(
		k.p,
		q.(*pointG2).p,
		&s.(*mod.Int).V,
	)
	return k
}

func (k *pointG2) MarshalBinary() ([]byte, error) {
	return bls12381.NewG2().ToCompressed(k.p), nil
}

func (k *pointG2) UnmarshalBinary(buff []byte) error {
	var err error
	k.p, err = bls12381.NewG2().FromCompressed(buff)
	return err
}

func (k *pointG2) MarshalTo(w io.Writer) (int, error) {
	buf, err := k.MarshalBinary()
	if err != nil {
		return 0, err
	}
	return w.Write(buf)
}

func (k *pointG2) UnmarshalFrom(r io.Reader) (int, error) {
	buf := make([]byte, k.MarshalSize())
	n, err := io.ReadFull(r, buf)
	if err != nil {
		return n, err
	}
	return n, k.UnmarshalBinary(buf)
}

func (k *pointG2) MarshalSize() int {
	return 96
}

func (k *pointG2) String() string {
	b, _ := k.MarshalBinary()
	return "bls12-381.G1: " + hex.EncodeToString(b)
}

func (k *pointG2) Hash(m []byte) kyber.Point {
	pg2, _ := bls12381.NewG2().HashToCurve(m, Domain)
	k.p = pg2
	return k
}

func sha256Hash(in []byte) []byte {
	h := sha256.New()
	h.Write(in)
	return h.Sum(nil)
}

func (k *pointG2) IsInCorrectGroup() bool {
	return bls12381.NewG2().InCorrectSubgroup(k.p)
}

type pointGT struct {
	f *bls12381.E
}

func newEmptyGT() *pointGT {
	return newPointGT(bls12381.NewGT().New())
}
func newPointGT(f *bls12381.E) *pointGT {
	return &pointGT{
		f: f,
	}
}

func (k *pointGT) Equal(kk kyber.Point) bool {
	return k.f.Equal(kk.(*pointGT).f)
}

const gtLength = 576

func (k *pointGT) Null() kyber.Point {
	var zero [gtLength]byte
	k.f, _ = bls12381.NewGT().FromBytes(zero[:])
	return k
}

func (k *pointGT) Base() kyber.Point {
	panic("not yet available")
}

func (k *pointGT) Pick(rand cipher.Stream) kyber.Point {
	panic("TODO: bls12-381.GT.Pick()")
}

func (k *pointGT) Set(q kyber.Point) kyber.Point {
	k.f.Set(q.(*pointGT).f)
	return k
}

func (k *pointGT) Clone() kyber.Point {
	kk := newEmptyGT()
	kk.Set(k)
	return kk
}

func (k *pointGT) Add(a, b kyber.Point) kyber.Point {
	aa := a.(*pointGT)
	bb := b.(*pointGT)
	bls12381.NewGT().Mul(k.f, aa.f, bb.f)
	return k
}

func (k *pointGT) Sub(a, b kyber.Point) kyber.Point {
	aa := a.(*pointGT)
	bb := b.(*pointGT)
	bls12381.NewGT().Sub(k.f, aa.f, bb.f)
	return k
}

func (k *pointGT) Neg(q kyber.Point) kyber.Point {
	panic("bls12-381: GT is not a full kyber.Point implementation")
}

func (k *pointGT) Mul(s kyber.Scalar, q kyber.Point) kyber.Point {
	panic("bls12-381: GT is not a full kyber.Point implementation")
}

func (k *pointGT) MarshalBinary() ([]byte, error) {
	return bls12381.NewGT().ToBytes(k.f), nil
}

func (k *pointGT) MarshalTo(w io.Writer) (int, error) {
	buf, err := k.MarshalBinary()
	if err != nil {
		return 0, err
	}
	return w.Write(buf)
}

func (k *pointGT) UnmarshalBinary(buf []byte) error {
	fe12, err := bls12381.NewGT().FromBytes(buf)
	k.f = fe12
	return err
}

func (k *pointGT) UnmarshalFrom(r io.Reader) (int, error) {
	buf := make([]byte, k.MarshalSize())
	n, err := io.ReadFull(r, buf)
	if err != nil {
		return n, err
	}
	return n, k.UnmarshalBinary(buf)
}

func (k *pointGT) MarshalSize() int {
	return 576
}

func (k *pointGT) String() string {
	b, _ := k.MarshalBinary()
	return "bls12-381.GT: " + hex.EncodeToString(b)
}

func (k *pointGT) EmbedLen() int {
	panic("bls12-381.GT.EmbedLen(): unsupported operation")
}

func (k *pointGT) Embed(data []byte, rand cipher.Stream) kyber.Point {
	panic("bls12-381.GT.Embed(): unsupported operation")
}

func (k *pointGT) Data() ([]byte, error) {
	panic("bls12-381.GT.Data(): unsupported operation")
}
