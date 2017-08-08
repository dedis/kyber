package pbc

import (
	"crypto/cipher"
	"errors"
	"io"
	"runtime"

	"github.com/dedis/kyber/abstract"
	"github.com/dfinity/go-dfinity-crypto/bls"

	"github.com/dedis/kyber/group"
	"github.com/dedis/kyber/random"
	"gopkg.in/dedis/kyber.v1"
)

type pointG1 struct {
	g         bls.G1
	generator string
}

func newPointG1(gen string) *pointG1 {
	pg1 := &pointG1{g: bls.G1{}, generator: gen}
	runtime.SetFinalizer(&pg1.g, clear)
	return pg1
}

func (p *pointG1) Equal(p2 abstract.Point) bool {
	pg := p2.(*pointG1)
	return p.g.IsEqual(&pg.g)
}

func (p *pointG1) Null() abstract.Point {
	p.g.Clear()
	return p
}

func (p *pointG1) Base() abstract.Point {
	if err := p.g.HashAndMapTo([]byte(p.generator)); err != nil {
		panic(err)
	}
	return p
}

func (p *pointG1) Add(p1, p2 abstract.Point) abstract.Point {
	pg1 := p1.(*pointG1)
	pg2 := p2.(*pointG1)
	bls.G1Add(&p.g, &pg1.g, &pg2.g)
	return p
}

func (p *pointG1) Sub(p1, p2 abstract.Point) abstract.Point {
	pg1 := p1.(*pointG1)
	pg2 := p2.(*pointG1)
	bls.G1Sub(&p.g, &pg1.g, &pg2.g)
	return p
}

func (p *pointG1) Neg(p1 abstract.Point) abstract.Point {
	pg1 := p1.(*pointG1)
	bls.G1Neg(&p.g, &pg1.g)
	return p
}

func (p *pointG1) Mul(p1 abstract.Point, s abstract.Scalar) abstract.Point {
	if p1 == nil {
		p1 = newPointG1(p.generator).Base()
	}
	sc := s.(*scalar)
	pg1 := p1.(*pointG1)
	bls.G1Mul(&p.g, &pg1.g, &sc.fe)
	return p
}

func (p *pointG1) MarshalBinary() (buff []byte, err error) {
	return marshalBinary(&p.g)
}

func (p *pointG1) MarshalTo(w io.Writer) (int, error) {
	return group.PointMarshalTo(p, w)
}

func (p *pointG1) UnmarshalBinary(buff []byte) error {
	return p.g.Deserialize(buff)
}

func (p *pointG1) UnmarshalFrom(r io.Reader) (int, error) {
	return group.PointUnmarshalFrom(p, r)
}

func (p *pointG1) MarshalSize() int {
	return bls.GetOpUnitSize() * 8
}

func (p *pointG1) String() string {
	return p.g.GetString(16)
}

func (p *pointG1) Pick(buff []byte, rand cipher.Stream) (abstract.Point, []byte) {
	return p.Embed(buff, rand)
}

func (p *pointG1) PickLen() int {
	// 8 bits for the randomness and 8 bits for the size of the message
	return (bls.GetOpUnitSize() * 8) - 1 - 1
}

func (p *pointG1) Embed(data []byte, rand cipher.Stream) (abstract.Point, []byte) {
	res := embed(p, data, rand)
	return p, res
}

func (p *pointG1) Data() ([]byte, error) {
	return data(p)
}

func (p *pointG1) Clone() abstract.Point {
	p2 := clone(p, newPointG1(p.generator))
	return p2.(abstract.Point)
}

func (p *pointG1) Set(p2 abstract.Point) abstract.Point {
	clone(p2, p)
	return p
}

type pointG2 struct {
	g         bls.G2
	generator string
}

func newPointG2(gen string) *pointG2 {
	pg := &pointG2{g: bls.G2{}, generator: gen}
	runtime.SetFinalizer(&pg.g, clear)
	return pg
}

func (p *pointG2) Equal(p2 abstract.Point) bool {
	pg := p2.(*pointG2)
	return p.g.IsEqual(&pg.g)
}

func (p *pointG2) Null() abstract.Point {
	p.g.Clear()
	return p
}

func (p *pointG2) Base() abstract.Point {
	if err := p.g.HashAndMapTo([]byte(p.generator)); err != nil {
		panic(err)
	}
	return p
}

func (p *pointG2) Add(p1, p2 abstract.Point) abstract.Point {
	pg1 := p1.(*pointG2)
	pg2 := p2.(*pointG2)
	bls.G2Add(&p.g, &pg1.g, &pg2.g)
	return p
}

func (p *pointG2) Sub(p1, p2 abstract.Point) abstract.Point {
	pg1 := p1.(*pointG2)
	pg2 := p2.(*pointG2)
	bls.G2Sub(&p.g, &pg1.g, &pg2.g)
	return p
}

func (p *pointG2) Neg(p1 abstract.Point) abstract.Point {
	pg1 := p1.(*pointG2)
	bls.G2Neg(&p.g, &pg1.g)
	return p
}

func (p *pointG2) Mul(p1 abstract.Point, s abstract.Scalar) abstract.Point {
	if p1 == nil {
		p1 = newPointG2(p.generator).Base()
	}
	sc := s.(*scalar)
	pg1 := p1.(*pointG2)
	bls.G2Mul(&p.g, &pg1.g, &sc.fe)
	return p
}

func (p *pointG2) MarshalBinary() (buff []byte, err error) {
	return marshalBinary(&p.g)
}

func (p *pointG2) MarshalTo(w io.Writer) (int, error) {
	return group.PointMarshalTo(p, w)
}

func (p *pointG2) UnmarshalBinary(buff []byte) error {
	return p.g.Deserialize(buff)
}

func (p *pointG2) UnmarshalFrom(r io.Reader) (int, error) {
	return group.PointUnmarshalFrom(p, r)
}

func (p *pointG2) MarshalSize() int {
	return bls.GetOpUnitSize() * 8 * 2
}

func (p *pointG2) String() string {
	return p.g.GetString(16)
}

func (p *pointG2) Pick(buff []byte, rand cipher.Stream) (abstract.Point, []byte) {
	if err := p.g.HashAndMapTo(buff); err != nil {
		panic(err)
	}
	return p, nil

	//return p.Embed(nil, rand)
}

func (p *pointG2) PickLen() int {
	// 8 bits for the randomness and 8 bits for the size of the message
	return p.MarshalSize() - 1 - 1
}

func (p *pointG2) Embed(data []byte, rand cipher.Stream) abstract.Point {
	panic("not working for the moment")
	embed(p, data, rand)
	return p
}

func (p *pointG2) Clone() abstract.Point {
	p2 := clone(p, newPointG2(p.generator))
	return p2.(abstract.Point)
}

func (p *pointG2) Data() ([]byte, error) {
	return data(p)
}

func (p *pointG2) Set(p2 abstract.Point) abstract.Point {
	clone(p2, p)
	return p
}

type pointGT struct {
	g bls.GT
	p *Pairing
}

func newPointGT(p *Pairing) *pointGT {
	pg := &pointGT{g: bls.GT{}, p: p}
	runtime.SetFinalizer(&pg.g, clear)
	return pg
}

func (p *pointGT) Pairing(p1, p2 abstract.Point) abstract.Point {
	pg1 := p1.(*pointG1)
	pg2 := p2.(*pointG2)
	bls.Pairing(&p.g, &pg1.g, &pg2.g)
	return p
}

func (p *pointGT) Equal(p2 abstract.Point) bool {
	pg := p2.(*pointGT)
	return p.g.IsEqual(&pg.g)
}

func (p *pointGT) Null() abstract.Point {
	// multiplicative identity
	p.g.SetInt64(1)
	//p.g.Clear()
	return p
}

// Base point for GT is the point computed using the pairing operation
// over the base point of G1 and G2.
// XXX Is this desirable ? A fixed pre-computed point would be nicer.
// TODO precompute the pairing for each suite...
func (p *pointGT) Base() abstract.Point {
	g1 := p.p.G1().Point().Base()
	g2 := p.p.G2().Point().Base()
	return p.Pairing(g1, g2)
}

func (p *pointGT) Add(p1, p2 abstract.Point) abstract.Point {
	pg1 := p1.(*pointGT)
	pg2 := p2.(*pointGT)
	bls.GTMul(&p.g, &pg1.g, &pg2.g)
	return p
}

func (p *pointGT) Sub(p1, p2 abstract.Point) abstract.Point {
	pg1 := p1.(*pointGT)
	pg2 := p2.(*pointGT)
	bls.GTDiv(&p.g, &pg1.g, &pg2.g)
	return p
}

func (p *pointGT) Neg(p1 abstract.Point) abstract.Point {
	pg1 := p1.(*pointGT)
	bls.GTInv(&p.g, &pg1.g)
	return p
}

func (p *pointGT) Mul(p1 abstract.Point, s abstract.Scalar) abstract.Point {
	if p1 == nil {
		p1 = newPointGT(p.p).Base()
	}
	sc := s.(*scalar)
	pg1 := p1.(*pointGT)
	bls.GTPow(&p.g, &pg1.g, &sc.fe)
	return p
}

func (p *pointGT) MarshalBinary() (buff []byte, err error) {
	return marshalBinary(&p.g)
}

func (p *pointGT) MarshalTo(w io.Writer) (int, error) {
	return group.PointMarshalTo(p, w)
}

func (p *pointGT) UnmarshalBinary(buff []byte) error {
	return p.g.Deserialize(buff)
}

func (p *pointGT) UnmarshalFrom(r io.Reader) (int, error) {
	return group.PointUnmarshalFrom(p, r)
}

func (p *pointGT) MarshalSize() int {
	return bls.GetOpUnitSize() * 8 * 12
}

func (p *pointGT) String() string {
	return p.g.GetString(16)
}

func (p *pointGT) Pick(buff []byte, rand cipher.Stream) (abstract.Point, []byte) {
	return p.Embed(buff, rand)
}

func (p *pointGT) PickLen() int {
	// 8 bits for the randomness and 8 bits for the size of the message
	return (bls.GetOpUnitSize() * 8 * 12) - 1 - 1
}

func (p *pointGT) Embed(data []byte, rand cipher.Stream) (abstract.Point, []byte) {
	res := embed(p, data, rand)
	return p, res
}

func (p *pointGT) Clone() abstract.Point {
	p2 := clone(p, newPointGT(p.p))
	return p2.(abstract.Point)
}

func (p *pointGT) Data() ([]byte, error) {
	return data(p)
}

func (p *pointGT) Set(p2 abstract.Point) abstract.Point {
	clone(p2, p)
	return p
}

type pbcPoint interface {
	kyber.Marshaling
	PickLen() int
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

func embed(p pbcPoint, data []byte, rand cipher.Stream) []byte {
	buffSize := p.MarshalSize() // how much data + len + random can we embed
	embedSize := p.PickLen()    // how much data can we embed
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
		return data[embedSize:]
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
	if dl > p.PickLen() {
		return nil, errors.New("invalid embedded data length")
	}
	return buff[1 : 1+dl], nil
}

func clear(p clearable) {
	p.Clear()
}

var ErrVarTime = errors.New("no constant time implementation available")

func (p *pointG1) SetVarTime(varTime bool) error {
	return ErrVarTime
}

func (p *pointG2) SetVarTime(varTime bool) error {
	return ErrVarTime
}
func (p *pointGT) SetVarTime(varTime bool) error {
	return ErrVarTime
}
