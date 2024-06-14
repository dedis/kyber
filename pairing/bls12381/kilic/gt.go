package kilic

import (
	"crypto/cipher"
	"encoding/hex"
	"io"

	bls12381 "github.com/kilic/bls12-381"
	"go.dedis.ch/kyber/v4"
	"go.dedis.ch/kyber/v4/group/mod"
)

// GTElt contains a Gt element from the Kilic BLS12-381 curve
type GTElt struct {
	f *bls12381.E
}

func newEmptyGT() *GTElt {
	return newGT(bls12381.NewGT().New())
}
func newGT(f *bls12381.E) *GTElt {
	return &GTElt{
		f: f,
	}
}

func (k *GTElt) Equal(kk kyber.Point) bool {
	return k.f.Equal(kk.(*GTElt).f)
}

func (k *GTElt) Null() kyber.Point {
	// One since we deal with Gt elements as a multiplicative group only
	// i.e. Add in kyber -> mul in kilic/, Neg in kyber -> inverse in kilic/ etc
	k.f = bls12381.NewGT().New()
	return k
}

func (k *GTElt) Base() kyber.Point {
	panic("bls12-381.GT.Base(): unsupported operation")
}

func (k *GTElt) Pick(_ cipher.Stream) kyber.Point {
	panic("bls12-381.GT.Pick(): unsupported operation")
}

func (k *GTElt) Set(q kyber.Point) kyber.Point {
	k.f.Set(q.(*GTElt).f)
	return k
}

func (k *GTElt) Clone() kyber.Point {
	kk := newEmptyGT()
	kk.Set(k)
	return kk
}

func (k *GTElt) Add(a, b kyber.Point) kyber.Point {
	aa := a.(*GTElt)
	bb := b.(*GTElt)
	bls12381.NewGT().Mul(k.f, aa.f, bb.f)
	return k
}

func (k *GTElt) Sub(a, b kyber.Point) kyber.Point {
	nb := newEmptyGT().Neg(b)
	return newEmptyGT().Add(a, nb)
}

func (k *GTElt) Neg(q kyber.Point) kyber.Point {
	qq := q.(*GTElt)
	bls12381.NewGT().Inverse(k.f, qq.f)
	return k
}

func (k *GTElt) Mul(s kyber.Scalar, q kyber.Point) kyber.Point {
	v := s.(*mod.Int).V
	qq := q.(*GTElt)
	bls12381.NewGT().Exp(k.f, qq.f, &v)
	return k
}

// MarshalBinary returns a compressed point, without any domain separation tag information
func (k *GTElt) MarshalBinary() ([]byte, error) {
	return bls12381.NewGT().ToBytes(k.f), nil
}

// MarshalTo writes a compressed point to the Writer, without any domain separation tag information
func (k *GTElt) MarshalTo(w io.Writer) (int, error) {
	buf, err := k.MarshalBinary()
	if err != nil {
		return 0, err
	}
	return w.Write(buf)
}

// UnmarshalBinary populates the point from a compressed point representation.
func (k *GTElt) UnmarshalBinary(buf []byte) error {
	fe12, err := bls12381.NewGT().FromBytes(buf)
	k.f = fe12
	return err
}

// UnmarshalFrom populates the point from a compressed point representation read from the Reader.
func (k *GTElt) UnmarshalFrom(r io.Reader) (int, error) {
	buf := make([]byte, k.MarshalSize())
	n, err := io.ReadFull(r, buf)
	if err != nil {
		return n, err
	}
	return n, k.UnmarshalBinary(buf)
}

func (k *GTElt) MarshalSize() int {
	return 576
}

func (k *GTElt) String() string {
	b, _ := k.MarshalBinary()
	return "bls12-381.GT: " + hex.EncodeToString(b)
}

func (k *GTElt) EmbedLen() int {
	panic("bls12-381.GT.EmbedLen(): unsupported operation")
}

func (k *GTElt) Embed(_ []byte, _ cipher.Stream) kyber.Point {
	panic("bls12-381.GT.Embed(): unsupported operation")
}

func (k *GTElt) Data() ([]byte, error) {
	panic("bls12-381.GT.Data(): unsupported operation")
}
