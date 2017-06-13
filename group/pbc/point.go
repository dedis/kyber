package pbc

import (
	"crypto/cipher"
	"dfinity/crypto/bls"
	"errors"
	"io"
	"runtime"

	"gopkg.in/dedis/kyber.v1"
	"gopkg.in/dedis/kyber.v1/util/marshalling"
	"gopkg.in/dedis/kyber.v1/util/random"
)

type PointG1 struct {
	g         bls.G1
	generator string
}

func newPointG1(gen string) *PointG1 {
	pg1 := &PointG1{g: bls.G1{}, generator: gen}
	runtime.SetFinalizer(&pg1.g, clear)
	return pg1
}

func (p *PointG1) Equal(p2 kyber.Point) bool {
	pg := p2.(*PointG1)
	return p.g.IsEqual(&pg.g)
}

func (p *PointG1) Null() kyber.Point {
	p.g.Clear()
	return p
}

func (p *PointG1) Base() kyber.Point {
	if err := p.g.HashAndMapTo([]byte(p.generator)); err != nil {
		panic(err)
	}
	return p
}

func (p *PointG1) Add(p1, p2 kyber.Point) kyber.Point {
	pg1 := p1.(*PointG1)
	pg2 := p2.(*PointG1)
	bls.G1Add(&p.g, &pg1.g, &pg2.g)
	return p
}

func (p *PointG1) Sub(p1, p2 kyber.Point) kyber.Point {
	pg1 := p1.(*PointG1)
	pg2 := p2.(*PointG1)
	bls.G1Sub(&p.g, &pg1.g, &pg2.g)
	return p
}

func (p *PointG1) Neg(p1 kyber.Point) kyber.Point {
	pg1 := p1.(*PointG1)
	bls.G1Neg(&p.g, &pg1.g)
	return p
}

func (p *PointG1) Mul(s kyber.Scalar, p1 kyber.Point) kyber.Point {
	if p1 == nil {
		p1 = newPointG1(p.generator).Base()
	}
	sc := s.(*scalar)
	pg1 := p1.(*PointG1)
	bls.G1Mul(&p.g, &pg1.g, &sc.fe)
	return p
}

func (p *PointG1) MarshalBinary() (buff []byte, err error) {
	return marshalBinary(&p.g)
}

func (p *PointG1) MarshalTo(w io.Writer) (int, error) {
	return marshalling.PointMarshalTo(p, w)
}

func (p *PointG1) UnmarshalBinary(buff []byte) error {
	return p.g.Deserialize(buff)
}

func (p *PointG1) UnmarshalFrom(r io.Reader) (int, error) {
	return marshalling.PointUnmarshalFrom(p, r)
}

func (p *PointG1) MarshalSize() int {
	return bls.GetOpUnitSize() * 8
}

func (p *PointG1) String() string {
	return p.g.GetString(16)
}

func (p *PointG1) Pick(rand cipher.Stream) kyber.Point {
	return p.Embed(nil, rand)
}

func (p *PointG1) EmbedLen() int {
	// 8 bits for the randomness and 8 bits for the size of the message
	return (bls.GetOpUnitSize() * 8) - 1 - 1
}

func (p *PointG1) Embed(data []byte, rand cipher.Stream) kyber.Point {
	embed(p, data, rand)
	return p
}

func (p *PointG1) Data() ([]byte, error) {
	return data(p)
}

func (p *PointG1) Clone() kyber.Point {
	p2 := clone(p, newPointG1(p.generator))
	return p2.(kyber.Point)
}

func (p *PointG1) Set(p2 kyber.Point) kyber.Point {
	clone(p2, p)
	return p
}

type PointG2 struct {
	g         bls.G2
	generator string
}

func newPointG2(gen string) *PointG2 {
	pg := &PointG2{g: bls.G2{}, generator: gen}
	runtime.SetFinalizer(&pg.g, clear)
	return pg
}

func (p *PointG2) Equal(p2 kyber.Point) bool {
	pg := p2.(*PointG2)
	return p.g.IsEqual(&pg.g)
}

func (p *PointG2) Null() kyber.Point {
	p.g.Clear()
	return p
}

func (p *PointG2) Base() kyber.Point {
	if err := p.g.HashAndMapTo([]byte(p.generator)); err != nil {
		panic(err)
	}
	return p
}

func (p *PointG2) Add(p1, p2 kyber.Point) kyber.Point {
	pg1 := p1.(*PointG2)
	pg2 := p2.(*PointG2)
	bls.G2Add(&p.g, &pg1.g, &pg2.g)
	return p
}

func (p *PointG2) Sub(p1, p2 kyber.Point) kyber.Point {
	pg1 := p1.(*PointG2)
	pg2 := p2.(*PointG2)
	bls.G2Sub(&p.g, &pg1.g, &pg2.g)
	return p
}

func (p *PointG2) Neg(p1 kyber.Point) kyber.Point {
	pg1 := p1.(*PointG2)
	bls.G2Neg(&p.g, &pg1.g)
	return p
}

func (p *PointG2) Mul(s kyber.Scalar, p1 kyber.Point) kyber.Point {
	if p1 == nil {
		p1 = newPointG2(p.generator).Base()
	}
	sc := s.(*scalar)
	pg1 := p1.(*PointG2)
	bls.G2Mul(&p.g, &pg1.g, &sc.fe)
	return p
}

func (p *PointG2) MarshalBinary() (buff []byte, err error) {
	return marshalBinary(&p.g)
}

func (p *PointG2) MarshalTo(w io.Writer) (int, error) {
	return marshalling.PointMarshalTo(p, w)
}

func (p *PointG2) UnmarshalBinary(buff []byte) error {
	return p.g.Deserialize(buff)
}

func (p *PointG2) UnmarshalFrom(r io.Reader) (int, error) {
	return marshalling.PointUnmarshalFrom(p, r)
}

func (p *PointG2) MarshalSize() int {
	return bls.GetOpUnitSize() * 8 * 2
}

func (p *PointG2) String() string {
	return p.g.GetString(16)
}

func (p *PointG2) Pick(rand cipher.Stream) kyber.Point {
	buff := random.NonZeroBytes(32, rand)
	if err := p.g.HashAndMapTo(buff); err != nil {
		panic(err)
	}
	return p

	//return p.Embed(nil, rand)
}

func (p *PointG2) EmbedLen() int {
	// 8 bits for the randomness and 8 bits for the size of the message
	return (bls.GetOpUnitSize() * 8 * 2) - 1 - 1
}

func (p *PointG2) Embed(data []byte, rand cipher.Stream) kyber.Point {
	embed(p, data, rand)
	return p
}

func (p *PointG2) Clone() kyber.Point {
	p2 := clone(p, newPointG2(p.generator))
	return p2.(kyber.Point)
}

func (p *PointG2) Data() ([]byte, error) {
	return data(p)
}

func (p *PointG2) Set(p2 kyber.Point) kyber.Point {
	clone(p2, p)
	return p
}

type PointGT struct {
	g bls.GT
	p *Pairing
}

func newPointGT(p *Pairing) *PointGT {
	pg := &PointGT{g: bls.GT{}, p: p}
	runtime.SetFinalizer(&pg.g, clear)
	return pg
}

func (p *PointGT) Pairing(p1, p2 kyber.Point) kyber.Point {
	pg1 := p1.(*PointG1)
	pg2 := p2.(*PointG2)
	bls.Pairing(&p.g, &pg1.g, &pg2.g)
	return p
}

func (p *PointGT) Equal(p2 kyber.Point) bool {
	pg := p2.(*PointGT)
	return p.g.IsEqual(&pg.g)
}

func (p *PointGT) Null() kyber.Point {
	p.g.Clear()
	return p
}

// Base point for GT is the point computed using the pairing operation
// over the base point of G1 and G2.
// XXX Is this desirable ? A fixed pre-computed point would be nicer.
// TODO precompute the pairing for each suite...
func (p *PointGT) Base() kyber.Point {
	g1 := p.p.G1().Point().Base()
	g2 := p.p.G2().Point().Base()
	return p.Pairing(g1, g2)
}

func (p *PointGT) Add(p1, p2 kyber.Point) kyber.Point {
	pg1 := p1.(*PointGT)
	pg2 := p2.(*PointGT)
	bls.GTAdd(&p.g, &pg1.g, &pg2.g)
	return p
}

func (p *PointGT) Sub(p1, p2 kyber.Point) kyber.Point {
	pg1 := p1.(*PointGT)
	pg2 := p2.(*PointGT)
	bls.GTSub(&p.g, &pg1.g, &pg2.g)
	return p
}

func (p *PointGT) Neg(p1 kyber.Point) kyber.Point {
	pg1 := p1.(*PointGT)
	bls.GTNeg(&p.g, &pg1.g)
	return p
}

func (p *PointGT) Mul(s kyber.Scalar, p1 kyber.Point) kyber.Point {
	if p1 == nil {
		p1 = newPointGT(p.generator).Base()
	}
	sc := s.(*scalar)
	pg1 := p1.(*PointGT)
	bls.GTPow(&p.g, &pg1.g, &sc.fe)
	return p
}

func (p *PointGT) MarshalBinary() (buff []byte, err error) {
	return marshalBinary(&p.g)
}

func (p *PointGT) MarshalTo(w io.Writer) (int, error) {
	return marshalling.PointMarshalTo(p, w)
}

func (p *PointGT) UnmarshalBinary(buff []byte) error {
	return p.g.Deserialize(buff)
}

func (p *PointGT) UnmarshalFrom(r io.Reader) (int, error) {
	return marshalling.PointUnmarshalFrom(p, r)
}

func (p *PointGT) MarshalSize() int {
	return bls.GetOpUnitSize() * 8 * 12
}

func (p *PointGT) String() string {
	return p.g.GetString(16)
}

func (p *PointGT) Pick(rand cipher.Stream) kyber.Point {
	return p.Embed(nil, rand)
}

func (p *PointGT) EmbedLen() int {
	// 8 bits for the randomness and 8 bits for the size of the message
	return (bls.GetOpUnitSize() * 8 * 12) - 1 - 1
}

func (p *PointGT) Embed(data []byte, rand cipher.Stream) kyber.Point {
	embed(p, data, rand)
	return p
}

func (p *PointGT) Clone() kyber.Point {
	p2 := clone(p, newPointGT(p.generator))
	return p2.(kyber.Point)
}

func (p *PointGT) Data() ([]byte, error) {
	return data(p)
}

func (p *PointGT) Set(p2 kyber.Point) kyber.Point {
	clone(p2, p)
	return p
}

type pbcPoint interface {
	kyber.Marshaling
	EmbedLen() int
}

type serializable interface {
	Serialize() []byte
}

type clearable interface {
	Clear()
}

func marshalBinary(p serializable) (buff []byte, err error) {
	defer func() {
		if e := recover(); e != nil {
			buff = nil
			err = e.(error)
		}
	}()
	buff = p.Serialize()
	return

}

func embed(p pbcPoint, data []byte, rand cipher.Stream) {
	buffSize := p.MarshalSize() // how much data + len + random can we embed
	embedSize := p.EmbedLen()   // how much data can we embed
	if embedSize > len(data) {
		embedSize = len(data)
	}

	for {
		// try filling in random bytes
		// XXX could be optimized by keeping one buffer and doing the "random"
		// part ourselves.
		buff := random.NonZeroBytes(buffSize, rand)
		if data != nil {
			buff[0] = byte(embedSize)       // encode length in low 8 bits
			copy(buff[1:1+embedSize], data) // copy data
		}

		err := p.UnmarshalBinary(buff)
		if err != nil {
			// no luck, try again
			continue
		}

		// Points live in a prime order curve so no cofactor-thing needed. All ok.
		return
	}
}

func clone(p, p2 pbcPoint) pbcPoint {
	buff, err := p.MarshalBinary()
	if err != nil {
		panic(err)
	}
	err = p2.UnmarshalBinary(buff)
	if err != nil {
		panic(err)
	}
	return p2
}

func data(p pbcPoint) ([]byte, error) {
	buff, _ := p.MarshalBinary()
	dl := int(buff[0]) // extract length byte
	if dl > p.EmbedLen() {
		return nil, errors.New("invalid embedded data length")
	}
	return buff[1 : 1+dl], nil
}

func clear(p clearable) {
	p.Clear()
}
